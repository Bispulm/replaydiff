package capture

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

// Reasons a body wasn't stored because of limits on capture itself. Redaction
// has its own set, in package redact.
const (
	// ReasonBodyTooLarge means the body exceeded the configured size limit.
	ReasonBodyTooLarge = "body_too_large"
	// ReasonMemoryBudget means capture's total memory budget was exhausted.
	ReasonMemoryBudget = "memory_budget"
	// ReasonIncomplete means the body wasn't seen through to its end.
	ReasonIncomplete = "incomplete_on_wire"
)

// memoryBudget bounds the bytes held across all in-flight and queued bodies.
// Acquire never blocks, because forwarding must never wait for it.
type memoryBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *memoryBudget) tryAcquire(n int64) bool {
	for {
		used := b.used.Load()
		if used+n > b.limit {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

func (b *memoryBudget) release(n int64) {
	if n != 0 {
		b.used.Add(-n)
	}
}

// bodyTap keeps a bounded copy of the bytes passing through a body. Its mutex
// is needed because a transport may keep reading a request body from another
// goroutine after the round trip returns, which also means reads can continue
// after seal. Those are ignored.
type bodyTap struct {
	limit  int64
	budget *memoryBudget

	mu         sync.Mutex
	buf        []byte
	charged    int64
	observed   int64
	dropReason string
	eof        bool
	readFailed bool
	sealed     bool
}

func newBodyTap(limit int64, budget *memoryBudget) *bodyTap {
	return &bodyTap{limit: limit, budget: budget}
}

func (t *bodyTap) observe(p []byte, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sealed {
		return
	}
	switch {
	case errors.Is(err, io.EOF):
		t.eof = true
	case err != nil:
		t.readFailed = true
	}
	if len(p) == 0 {
		return
	}
	t.observed += int64(len(p))
	if t.dropReason != "" {
		return
	}
	need := int64(len(t.buf) + len(p))
	if need > t.limit {
		t.drop(ReasonBodyTooLarge)
		return
	}
	if need > int64(cap(t.buf)) && !t.grow(need) {
		t.drop(ReasonMemoryBudget)
		return
	}
	t.buf = append(t.buf, p...)
}

// grow reallocates so the budget tracks real capacity, not the visible length.
func (t *bodyTap) grow(need int64) bool {
	newCap := min(max(need, 2*int64(cap(t.buf)), 4<<10), t.limit)
	extra := newCap - t.charged
	if !t.budget.tryAcquire(extra) {
		// Doubling may have asked for more than necessary, so try the minimum.
		newCap = need
		extra = newCap - t.charged
		if !t.budget.tryAcquire(extra) {
			return false
		}
	}
	grown := make([]byte, len(t.buf), newCap)
	copy(grown, t.buf)
	t.buf = grown
	t.charged = newCap
	return true
}

func (t *bodyTap) drop(reason string) {
	t.dropReason = reason
	t.budget.release(t.charged)
	t.charged = 0
	t.buf = nil
}

// bodyCapture is what a sealed tap observed.
type bodyCapture struct {
	data       []byte
	charged    int64
	observed   int64
	dropReason string
	eof        bool
	readFailed bool
}

// seal stops observing and hands the buffer over. The caller takes over
// returning the charged bytes to the budget.
func (t *bodyTap) seal() bodyCapture {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sealed = true
	out := bodyCapture{
		data:       t.buf,
		charged:    t.charged,
		observed:   t.observed,
		dropReason: t.dropReason,
		eof:        t.eof,
		readFailed: t.readFailed,
	}
	t.buf = nil
	t.charged = 0
	return out
}

// teeBody copies what is read into a tap on the way through.
type teeBody struct {
	io.ReadCloser
	tap *bodyTap
}

func (b *teeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.tap.observe(p[:n], err)
	return n, err
}
