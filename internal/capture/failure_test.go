package capture

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

// controlFS wraps real storage with failures a test switches on and off.
type controlFS struct {
	traffic.FS
	gate     chan struct{} // while non-nil, writes block until it is closed.
	mu       sync.Mutex
	writeErr error
	writes   atomic.Int64
	blocked  atomic.Int64
}

type controlFile struct {
	traffic.File
	fs *controlFS
}

func (c *controlFS) Create(name string) (traffic.File, error) {
	file, err := c.FS.Create(name)
	if err != nil {
		return nil, err
	}
	return &controlFile{File: file, fs: c}, nil
}

func (c *controlFS) setWriteErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeErr = err
}

func (f *controlFile) Write(p []byte) (int, error) {
	f.fs.writes.Add(1)
	if f.fs.gate != nil {
		f.fs.blocked.Add(1)
		<-f.fs.gate
		f.fs.blocked.Add(-1)
	}
	f.fs.mu.Lock()
	err := f.fs.writeErr
	f.fs.mu.Unlock()
	if err != nil {
		// A partial write, as a filling disk really produces.
		n, werr := f.File.Write(p[:len(p)/2])
		if werr != nil {
			return n, werr
		}
		return n, err
	}
	return f.File.Write(p)
}

func withControlFS(t *testing.T, gate chan struct{}) (func(*Config), *controlFS) {
	t.Helper()
	control := &controlFS{gate: gate}
	return func(cfg *Config) {
		base, err := traffic.OpenDirFS(cfg.Dir)
		if err != nil {
			t.Fatal(err)
		}
		control.FS = base
		cfg.FS = control
	}, control
}

func withLimits(f func(*Limits)) func(*Config) {
	return func(cfg *Config) { f(&cfg.Limits) }
}

func TestSecretsInEveryCoveredLocationNeverPersist(t *testing.T) {
	var (
		authHeader    = sentinel(t)
		cookieHeader  = sentinel(t)
		apiKeyHeader  = sentinel(t)
		setCookie     = sentinel(t)
		queryValue    = sentinel(t)
		requestEmail  = sentinel(t)
		requestDeep   = sentinel(t)
		responseEmail = sentinel(t)
		responseCard  = sentinel(t)
		compressed    = sentinel(t)
		location      = sentinel(t)
	)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := fmt.Fprintf(zw, `{"user":{"email":%q,"id":1}}`, compressed); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var upstreamSaw string
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSaw = r.Header.Get("Authorization")
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Set-Cookie", "sid="+setCookie)
		w.Header().Set("Location", "/next?token="+location)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/compressed" {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz.Bytes())
			return
		}
		fmt.Fprintf(w, `{"user":{"email":%q},"items":[{"card":%q}],"ok":true}`, responseEmail, responseCard)
	}))
	header := map[string]string{
		"Authorization": "Bearer " + authHeader,
		"Cookie":        "sid=" + cookieHeader,
		"X-Api-Key":     apiKeyHeader,
		"Content-Type":  "application/json",
	}
	got := h.send(http.MethodPost, "/orders?token="+queryValue+"&page=2",
		[]byte(fmt.Sprintf(`{"user":{"email":%q},"nested":{"password":%q},"sku":"a"}`, requestEmail, requestDeep)), header)
	if !bytes.Contains(got.body, []byte(responseEmail)) {
		t.Fatalf("live response must be untouched: %s", got.body)
	}
	if upstreamSaw != "Bearer "+authHeader {
		t.Fatalf("live request must be untouched: %q", upstreamSaw)
	}
	h.send(http.MethodGet, "/compressed", nil, nil)

	records := h.records()
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	h.assertNoSecret(authHeader, cookieHeader, apiKeyHeader, setCookie, queryValue, requestEmail, requestDeep,
		responseEmail, responseCard, compressed, location)

	first := records[0]
	if first.Request.RawQuery != "token=REDACTED&page=2" {
		t.Fatalf("query = %q", first.Request.RawQuery)
	}
	if !strings.Contains(string(first.Request.Body.Data), `"sku":"a"`) {
		t.Fatalf("unrelated field lost: %s", first.Request.Body.Data)
	}
	if !strings.Contains(string(first.Response.Body.Data), `"ok":true`) {
		t.Fatalf("unrelated field lost: %s", first.Response.Body.Data)
	}
	if first.SessionKey == "" {
		t.Fatal("session key not derived from the cookie")
	}
	if len(first.Redaction.Hits) == 0 || !first.Redaction.Complete || first.Redaction.PolicyDigest == "" {
		t.Fatalf("redaction = %+v", first.Redaction)
	}
	if !first.Replay.Eligible {
		t.Fatalf("replay = %+v", first.Replay)
	}
	second := records[1]
	if second.Response.Body.OriginalEncoding != "gzip" || !strings.Contains(string(second.Response.Body.Data), `"id":1`) {
		t.Fatalf("compressed body = %+v", second.Response.Body)
	}
}

func TestMalformedRequestBodyIsForwardedButNeverStored(t *testing.T) {
	secret := sentinel(t)
	body := []byte(`{"user":{"email":"` + secret)
	var seen []byte
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen, _ = io.ReadAll(r.Body) }))
	h.send(http.MethodPost, "/", body, map[string]string{"Content-Type": "application/json"})
	if !bytes.Equal(seen, body) {
		t.Fatalf("upstream saw %q", seen)
	}
	rec := h.onlyRecord()
	if rec.Request.Body.State != traffic.BodyOmitted || rec.Request.Body.Reason != "malformed_json" {
		t.Fatalf("body = %+v", rec.Request.Body)
	}
	if rec.Replay.Eligible || rec.Redaction.Complete {
		t.Fatalf("replay = %+v, redaction = %+v", rec.Replay, rec.Redaction)
	}
	h.assertNoSecret(secret)
	if h.capture.Stats().BodiesOmitted["malformed_json"] != 1 {
		t.Fatalf("stats = %+v", h.capture.Stats())
	}
}

func TestMalformedResponseBodyIsForwardedButNeverStored(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, jsonHandler(`{"user":{"email":"`+secret))
	got := h.send(http.MethodGet, "/", nil, nil)
	if !bytes.Contains(got.body, []byte(secret)) {
		t.Fatalf("client body = %q", got.body)
	}
	rec := h.onlyRecord()
	if rec.Response.Body.State != traffic.BodyOmitted || rec.Replay.Eligible {
		t.Fatalf("record = %+v", rec)
	}
	h.assertNoSecret(secret)
}

func TestUnsupportedRequestContentTypeIsNotStoredOrReplayable(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	h.send(http.MethodPost, "/", []byte(secret), map[string]string{"Content-Type": "text/plain"})
	rec := h.onlyRecord()
	if rec.Request.Body.State != traffic.BodyOmitted || rec.Request.Body.Reason != "unsupported_content_type" || rec.Replay.Eligible {
		t.Fatalf("record = %+v", rec)
	}
	h.assertNoSecret(secret)
}

func TestUnsupportedResponseContentTypeKeepsRequestReplayable(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, secret)
	}))
	h.send(http.MethodGet, "/", nil, nil)
	rec := h.onlyRecord()
	if rec.Response.Body.State != traffic.BodyOmitted || !rec.Replay.Eligible {
		t.Fatalf("record = %+v", rec)
	}
	h.assertNoSecret(secret)
}

func TestOversizedBodiesAreForwardedInFullButNotStored(t *testing.T) {
	secret := sentinel(t)
	large := bytes.Repeat([]byte(secret), 1000)
	var seen int
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		seen = len(data)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(large)
	}), withLimits(func(l *Limits) {
		l.MaxRequestBodyBytes = 1024
		l.MaxResponseBodyBytes = 1024
	}))
	got := h.send(http.MethodPost, "/", large, map[string]string{"Content-Type": "application/json"})
	if seen != len(large) || len(got.body) != len(large) {
		t.Fatalf("upstream saw %d bytes, client saw %d, want %d", seen, len(got.body), len(large))
	}
	rec := h.onlyRecord()
	if rec.Request.Body.State != traffic.BodyOmitted || rec.Request.Body.Reason != ReasonBodyTooLarge {
		t.Fatalf("request body = %+v", rec.Request.Body)
	}
	if rec.Request.Body.ObservedBytes != int64(len(large)) {
		t.Fatalf("observed = %d, want the full size", rec.Request.Body.ObservedBytes)
	}
	if rec.Response.Body.State != traffic.BodyOmitted || rec.Response.Body.Reason != ReasonBodyTooLarge {
		t.Fatalf("response body = %+v", rec.Response.Body)
	}
	if rec.Replay.Eligible {
		t.Fatal("an unrecorded request body can't be replayed")
	}
	h.assertNoSecret(secret)
}

func TestMemoryBudgetBoundsBufferedBodiesAndForwardingContinues(t *testing.T) {
	gate := make(chan struct{})
	adjust, _ := withControlFS(t, gate)
	const budget = 8 << 10
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}), adjust, withLimits(func(l *Limits) {
		l.MemoryBudgetBytes = budget
		l.QueueCapacity = 1000
		l.Workers = 1
	}))
	body := []byte(`{"data":"` + strings.Repeat("x", 2<<10) + `"}`)
	for range 50 {
		// Storage is blocked, so nothing is released: the budget must hold.
		if got := h.send(http.MethodPost, "/", body, map[string]string{"Content-Type": "application/json"}); got.status != http.StatusOK {
			t.Fatalf("status = %d", got.status)
		}
		if used := h.capture.Stats().MemoryBudgetUsedBytes; used > budget {
			t.Fatalf("budget used = %d, limit %d", used, budget)
		}
	}
	close(gate)
	h.close()
	stats := h.capture.Stats()
	if used := stats.MemoryBudgetUsedBytes; used != 0 {
		t.Fatalf("budget not returned: %d bytes in use", used)
	}
	// Counted when a queued exchange is processed, so only after storage resumes.
	if stats.BodiesOmitted[ReasonMemoryBudget] == 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestSaturatedQueueDropsRecordsAndNeverDelaysClients(t *testing.T) {
	gate := make(chan struct{})
	adjust, control := withControlFS(t, gate)
	h := newHarness(t, jsonHandler(`{"ok":true}`), adjust, withLimits(func(l *Limits) {
		l.QueueCapacity = 2
		l.Workers = 1
	}))
	start := time.Now()
	const requests = 100
	for range requests {
		if got := h.send(http.MethodGet, "/", nil, nil); got.status != http.StatusOK {
			t.Fatalf("status = %d", got.status)
		}
	}
	// Writes are blocked for this whole loop. Anything waiting on storage would
	// hang here, so finishing at all is the main assertion.
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("%d requests took %v with storage blocked", requests, elapsed)
	}
	waitFor(t, "writer to block on storage", func() bool { return control.blocked.Load() > 0 })

	stats := h.capture.Stats()
	if stats.Dropped[string(DropQueueFull)] == 0 {
		t.Fatalf("stats = %+v", stats)
	}
	close(gate)
	h.close()
	stats = h.capture.Stats()
	if got := stats.Persisted + stats.Dropped[string(DropQueueFull)]; got != requests {
		t.Fatalf("persisted + queue_full = %d, want %d: %+v", got, requests, stats)
	}
}

func TestDiskFullDropsRecordsWithoutAffectingTrafficAndRecovers(t *testing.T) {
	adjust, control := withControlFS(t, nil)
	h := newHarness(t, jsonHandler(`{"ok":true}`), adjust, withLimits(func(l *Limits) {
		l.StorageRetryInterval = time.Millisecond
	}))
	if got := h.send(http.MethodGet, "/before", nil, nil); got.status != http.StatusOK {
		t.Fatalf("status = %d", got.status)
	}
	waitFor(t, "first record", func() bool { return h.capture.Stats().Persisted == 1 })

	control.setWriteErr(syscall.ENOSPC)
	for range 3 {
		if got := h.send(http.MethodGet, "/during", nil, nil); got.status != http.StatusOK {
			t.Fatalf("status during full disk = %d", got.status)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, "disk full drop", func() bool { return h.capture.Stats().Dropped[string(DropDiskFull)] > 0 })

	control.setWriteErr(nil)
	time.Sleep(5 * time.Millisecond)
	if got := h.send(http.MethodGet, "/after", nil, nil); got.status != http.StatusOK {
		t.Fatalf("status = %d", got.status)
	}
	waitFor(t, "recovery", func() bool { return h.capture.Stats().Persisted >= 2 })

	// A partial frame was truncated, so the dataset is clean apart from the
	// counted drops, and the drops travel with the data.
	records := h.records()
	got := paths(records)
	if len(got) != 2 || got[0] != "/before" || got[1] != "/after" {
		t.Fatalf("paths = %v", got)
	}
	ds, err := traffic.Scan(h.dir, traffic.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ds.Close() }()
	if ds.CaptureDrops[string(DropDiskFull)] == 0 {
		t.Fatalf("drops = %v", ds.CaptureDrops)
	}
}

func TestOtherWriteFailuresAreCountedSeparately(t *testing.T) {
	adjust, control := withControlFS(t, nil)
	h := newHarness(t, jsonHandler(`{"ok":true}`), adjust, withLimits(func(l *Limits) {
		l.StorageRetryInterval = time.Hour
	}))
	control.setWriteErr(syscall.EIO)
	for range 5 {
		h.send(http.MethodGet, "/", nil, nil)
		time.Sleep(2 * time.Millisecond)
	}
	waitFor(t, "write failure", func() bool {
		stats := h.capture.Stats()
		return stats.Dropped[string(DropWriteError)] == 1 && stats.Dropped[string(DropStorageBackoff)] >= 1
	})
	control.setWriteErr(nil)
}

func TestRecordOverSizeLimitIsDropped(t *testing.T) {
	h := newHarness(t, jsonHandler(`{"data":"`+strings.Repeat("x", 4096)+`"}`), withLimits(func(l *Limits) {
		l.MaxRecordBytes = 1024
	}))
	h.send(http.MethodGet, "/", nil, nil)
	waitFor(t, "drop", func() bool { return h.capture.Stats().Dropped[string(DropRecordTooLarge)] == 1 })
}

func TestProcessingDeadlineDropsStaleExchanges(t *testing.T) {
	gate := make(chan struct{})
	adjust, control := withControlFS(t, gate)
	h := newHarness(t, jsonHandler(`{}`), adjust, withLimits(func(l *Limits) {
		l.ProcessingDeadline = 10 * time.Millisecond
		l.Workers = 1
		l.QueueCapacity = 100
	}))
	for range 8 {
		h.send(http.MethodGet, "/", nil, nil)
	}
	waitFor(t, "writer to block", func() bool { return control.blocked.Load() > 0 })
	time.Sleep(50 * time.Millisecond)
	close(gate)
	h.close()
	if h.capture.Stats().Dropped[string(DropDeadlineExceeded)] == 0 {
		t.Fatalf("stats = %+v", h.capture.Stats())
	}
}

func TestFailureInSanitizingDropsTheRecordWithoutLeakingOrStopping(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, jsonHandler(`{}`))
	h.capture.sanitize = func(*exchange) *traffic.Record { panic("secret-bearing panic " + secret) }
	h.send(http.MethodGet, "/", nil, nil)
	waitFor(t, "drop", func() bool { return h.capture.Stats().Dropped[string(DropSanitizeFailure)] == 1 })

	h.capture.sanitize = h.capture.sanitizeExchange
	h.send(http.MethodGet, "/", nil, nil)
	waitFor(t, "worker survived", func() bool { return h.capture.Stats().Persisted == 1 })
	h.assertNoSecret(secret)
}

func TestLogsAtDebugLevelNeverHoldTrafficContent(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, jsonHandler(`{"user":{"email":"`+secret+`"}`), withLimits(func(l *Limits) {
		l.MaxRecordBytes = 64
	}))
	h.send(http.MethodPost, "/path/"+secret+"?token="+secret, []byte(`{"bad":"`+secret), map[string]string{
		"Content-Type":  "application/json",
		"Authorization": secret,
		"User-Agent":    secret,
	})
	waitFor(t, "drop", func() bool { return h.capture.Stats().Dropped[string(DropRecordTooLarge)] == 1 })
	h.close()
	if strings.Contains(h.logs.String(), secret) {
		t.Fatalf("logs hold traffic content:\n%s", h.logs.String())
	}
}

func TestShutdownDrainsQueuedRecordsAndSealsTheRun(t *testing.T) {
	h := newHarness(t, jsonHandler(`{"ok":true}`))
	for range 20 {
		h.send(http.MethodGet, "/", nil, nil)
	}
	records := h.records() // Fails on any integrity problem, including no final marker.
	if len(records) != 20 {
		t.Fatalf("records = %d", len(records))
	}
}

func TestExchangesAfterCloseAreCountedAndStillForwarded(t *testing.T) {
	h := newHarness(t, jsonHandler(`{}`))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.capture.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.send(http.MethodGet, "/", nil, nil); got.status != http.StatusOK {
		t.Fatalf("status = %d", got.status)
	}
	if h.capture.Stats().Dropped[string(DropShuttingDown)] != 1 {
		t.Fatalf("stats = %+v", h.capture.Stats())
	}
}

func TestCloseRespectsDeadlineWhenStorageIsStuckAndCleansUpAfter(t *testing.T) {
	baseline := runtime.NumGoroutine()
	gate := make(chan struct{})
	adjust, control := withControlFS(t, gate)
	h := newHarness(t, jsonHandler(`{}`), adjust, withLimits(func(l *Limits) { l.Workers = 2 }))
	for range 10 {
		h.send(http.MethodGet, "/", nil, nil)
	}
	waitFor(t, "writer to block", func() bool { return control.blocked.Load() > 0 })
	h.proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := h.capture.Close(ctx)
	if !errors.Is(err, ErrShutdownDeadline) {
		t.Fatalf("err = %v, want ErrShutdownDeadline", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Close took %v with a 100ms deadline", elapsed)
	}
	h.closed = true

	// Once the stuck write returns, every goroutine must exit.
	close(gate)
	h.upstream.Close()
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	waitForGoroutines(t, baseline)
	if h.capture.Stats().MemoryBudgetUsedBytes != 0 {
		t.Fatalf("stats = %+v", h.capture.Stats())
	}
}

func TestCloseIsIdempotentAndLeavesNoGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()
	h := newHarness(t, jsonHandler(`{}`))
	h.send(http.MethodGet, "/", nil, nil)
	h.close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.capture.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	h.upstream.Close()
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	waitForGoroutines(t, baseline)
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	h := newHarness(t, http.NotFoundHandler())
	engine := h.capture.engine
	target := h.capture.upstream
	dir := t.TempDir()
	withLimit := func(l Limits) Config { return Config{Upstream: target, Dir: dir, Engine: engine, Limits: l} }
	for name, cfg := range map[string]Config{
		"no upstream":                  {Dir: dir, Engine: engine},
		"no dir":                       {Upstream: target, Engine: engine},
		"no engine":                    {Upstream: target, Dir: dir},
		"negative queue":               withLimit(Limits{QueueCapacity: -1}),
		"negative workers":             withLimit(Limits{Workers: -1}),
		"negative request body":        withLimit(Limits{MaxRequestBodyBytes: -1}),
		"negative response body":       withLimit(Limits{MaxResponseBodyBytes: -1}),
		"negative memory budget":       withLimit(Limits{MemoryBudgetBytes: -1}),
		"negative processing deadline": withLimit(Limits{ProcessingDeadline: -1}),
		"negative retry interval":      withLimit(Limits{StorageRetryInterval: -1}),
		"negative sync interval":       withLimit(Limits{SyncInterval: -1}),
		"negative segment size":        withLimit(Limits{MaxSegmentBytes: -1}),
		"negative record size":         withLimit(Limits{MaxRecordBytes: -1}),
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
