// Package capture implements the recording reverse proxy.
//
// Forwarding and recording are separate. The request path only copies bytes
// into budgeted memory and makes one non-blocking queue send. Redaction,
// compression and disk writes all happen on background goroutines, so a stuck
// disk costs recordings and never delays a client.
package capture

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// DropReason says why an exchange wasn't recorded.
type DropReason string

// Drop reasons. Each has its own counter.
const (
	DropQueueFull           DropReason = "queue_full"
	DropShuttingDown        DropReason = "shutting_down"
	DropShutdownDeadline    DropReason = "shutdown_deadline"
	DropDeadlineExceeded    DropReason = "deadline_exceeded"
	DropDiskFull            DropReason = "disk_full"
	DropWriteError          DropReason = "write_error"
	DropStorageBackoff      DropReason = "storage_backoff"
	DropRecordTooLarge      DropReason = "record_too_large"
	DropInvalidRecord       DropReason = "invalid_record"
	DropEncodeError         DropReason = "encode_error"
	DropSanitizeFailure     DropReason = "sanitize_failure"
	DropUnsupportedProtocol DropReason = "unsupported_protocol"
)

var allDropReasons = []DropReason{
	DropQueueFull, DropShuttingDown, DropShutdownDeadline, DropDeadlineExceeded,
	DropDiskFull, DropWriteError, DropStorageBackoff, DropRecordTooLarge,
	DropInvalidRecord, DropEncodeError, DropSanitizeFailure, DropUnsupportedProtocol,
}

// ErrShutdownDeadline means Close gave up waiting. Queued records were dropped,
// and a goroutine may still be blocked in a write that the OS hasn't returned
// from. It exits when that write does.
var ErrShutdownDeadline = errors.New("capture shutdown deadline exceeded")

// Limits bounds everything capture can hold. Zero values select the defaults.
type Limits struct {
	// MaxRequestBodyBytes and MaxResponseBodyBytes limit a buffered body.
	// Larger bodies are forwarded in full and omitted from the record.
	MaxRequestBodyBytes  int64 // Default 1 MiB.
	MaxResponseBodyBytes int64 // Default 1 MiB.
	// MemoryBudgetBytes limits bytes held across all in-flight and queued
	// bodies. It is what bounds memory under many concurrent large bodies.
	MemoryBudgetBytes int64 // Default 256 MiB.
	// QueueCapacity is the number of finished exchanges awaiting a worker.
	QueueCapacity int // Default 1024.
	// Workers is the number of redaction and compression goroutines.
	Workers int // Default min(GOMAXPROCS, 4).
	// ProcessingDeadline drops an exchange still unwritten this long after it
	// finished, so a slow disk can't make a backlog of stale work.
	ProcessingDeadline time.Duration // Default 5s.
	// StorageRetryInterval is how long to drop records after a write failure
	// before trying storage again.
	StorageRetryInterval time.Duration // Default 1s.
	// SyncInterval is how often the current segment is flushed to disk.
	SyncInterval time.Duration // Default 1s.
	// MaxSegmentBytes is the rotation threshold.
	MaxSegmentBytes int64 // Default traffic.DefaultMaxSegmentBytes.
	// MaxRecordBytes limits one encoded record.
	MaxRecordBytes int // Default traffic.DefaultMaxRecordBytes.
}

func (l Limits) validate() error {
	switch {
	case l.MaxRequestBodyBytes < 0, l.MaxResponseBodyBytes < 0, l.MemoryBudgetBytes < 0,
		l.MaxSegmentBytes < 0, l.MaxRecordBytes < 0:
		return errors.New("capture: size limits must not be negative")
	case l.QueueCapacity < 0, l.Workers < 0:
		return errors.New("capture: queue capacity and workers must not be negative")
	case l.ProcessingDeadline < 0, l.StorageRetryInterval < 0, l.SyncInterval < 0:
		return errors.New("capture: durations must not be negative")
	}
	return nil
}

func (l Limits) withDefaults() Limits {
	l.MaxRequestBodyBytes = cmp.Or(l.MaxRequestBodyBytes, 1<<20)
	l.MaxResponseBodyBytes = cmp.Or(l.MaxResponseBodyBytes, 1<<20)
	l.MemoryBudgetBytes = cmp.Or(l.MemoryBudgetBytes, 256<<20)
	l.QueueCapacity = cmp.Or(l.QueueCapacity, 1024)
	l.Workers = cmp.Or(l.Workers, min(runtime.GOMAXPROCS(0), 4))
	l.ProcessingDeadline = cmp.Or(l.ProcessingDeadline, 5*time.Second)
	l.StorageRetryInterval = cmp.Or(l.StorageRetryInterval, time.Second)
	l.SyncInterval = cmp.Or(l.SyncInterval, time.Second)
	return l
}

// Config configures a Capture.
type Config struct {
	// Upstream is the service being fronted.
	Upstream *url.URL
	// Dir is where segments are written.
	Dir string
	// Engine sanitizes exchanges before they are encoded.
	Engine *redact.Engine
	// Limits bounds resource use.
	Limits Limits
	// UpstreamH2C sends to the upstream using HTTP/2 without TLS, with no fallback
	// to HTTP/1.1. It is for development, and requires an http:// upstream.
	UpstreamH2C bool
	// UpstreamTLS configures an https:// upstream, such as a private CA. HTTP/2
	// is negotiated through ALPN when the upstream offers it.
	UpstreamTLS *tls.Config
	// FS overrides segment storage.
	FS traffic.FS
	// Logger receives operational logs, which never hold traffic content.
	Logger *slog.Logger
}

// Stats is a snapshot of capture's counters.
type Stats struct {
	Observed              int64            `json:"observed"`
	Persisted             int64            `json:"persisted"`
	Dropped               map[string]int64 `json:"dropped,omitempty"`
	BodiesOmitted         map[string]int64 `json:"bodies_omitted,omitempty"`
	SyncFailures          int64            `json:"sync_failures,omitempty"`
	QueueDepth            int              `json:"queue_depth"`
	MemoryBudgetUsedBytes int64            `json:"memory_budget_used_bytes"`
}

// Capture is a recording reverse proxy. It implements http.Handler.
type Capture struct {
	upstream *url.URL
	engine   *redact.Engine
	limits   Limits
	logger   *slog.Logger
	proxy    *httputil.ReverseProxy
	budget   memoryBudget
	encoder  *traffic.Encoder
	writer   *traffic.Writer

	// sanitize is a field so a test can make it fail.
	sanitize func(*exchange) *traffic.Record

	seq      atomic.Uint64
	observed atomic.Int64
	// inflight counts requests still being served, so that Close can wait for them.
	inflight  atomic.Int64
	persisted atomic.Int64
	syncFails atomic.Int64
	drops     map[DropReason]*atomic.Int64
	warned    map[DropReason]*atomic.Bool

	omittedMu sync.Mutex
	omitted   map[string]int64

	// submitMu lets Close shut the queue while submit is sending to it. A send
	// never blocks, so holding the read lock can't stall the request path.
	submitMu sync.RWMutex
	closing  bool
	queue    chan *exchange
	frames   chan traffic.Frame

	workers   sync.WaitGroup
	abort     chan struct{}
	abortOnce sync.Once
	closeOnce sync.Once
	done      chan struct{}
	closeErr  error
}

// New validates cfg and starts capture's background goroutines.
func New(cfg Config) (*Capture, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("capture: upstream is required")
	case cfg.Dir == "" && cfg.FS == nil:
		return nil, errors.New("capture: output directory is required")
	case cfg.Engine == nil:
		return nil, errors.New("capture: redaction engine is required")
	case cfg.UpstreamH2C && cfg.Upstream.Scheme != "http":
		return nil, errors.New("capture: h2c needs an http:// upstream; https negotiates HTTP/2 by itself")
	}
	if err := cfg.Limits.validate(); err != nil {
		return nil, err
	}
	limits := cfg.Limits.withDefaults()
	encoder, err := traffic.NewEncoder(traffic.EncoderOptions{MaxRecordBytes: limits.MaxRecordBytes})
	if err != nil {
		return nil, err
	}
	writer, err := traffic.NewWriter(cfg.Dir, traffic.WriterOptions{MaxSegmentBytes: limits.MaxSegmentBytes, FS: cfg.FS})
	if err != nil {
		encoder.Close()
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	c := &Capture{
		upstream: cfg.Upstream,
		engine:   cfg.Engine,
		limits:   limits,
		logger:   logger,
		encoder:  encoder,
		writer:   writer,
		drops:    make(map[DropReason]*atomic.Int64, len(allDropReasons)),
		warned:   make(map[DropReason]*atomic.Bool, len(allDropReasons)),
		omitted:  make(map[string]int64),
		queue:    make(chan *exchange, limits.QueueCapacity),
		frames:   make(chan traffic.Frame, limits.Workers),
		abort:    make(chan struct{}),
		done:     make(chan struct{}),
	}
	c.budget.limit = limits.MemoryBudgetBytes
	c.sanitize = c.sanitizeExchange
	for _, reason := range allDropReasons {
		c.drops[reason] = new(atomic.Int64)
		c.warned[reason] = new(atomic.Bool)
	}
	c.proxy = c.newReverseProxy(newUpstreamTransport(cfg))

	c.workers.Add(limits.Workers)
	for range limits.Workers {
		go func() {
			defer c.workers.Done()
			for ex := range c.queue {
				c.process(ex)
			}
		}()
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writeLoop()
	}()
	go func() {
		c.workers.Wait()
		close(c.frames)
		<-writerDone
		close(c.done)
	}()
	return c, nil
}

func newUpstreamTransport(cfg Config) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	// The upstream is explicit config. An ambient proxy variable mustn't redirect
	// live traffic.
	t.Proxy = nil
	// The client's own Accept-Encoding is forwarded, and compressed bytes pass
	// through untouched.
	t.DisableCompression = true
	t.MaxIdleConnsPerHost = 256
	t.TLSClientConfig = cfg.UpstreamTLS.Clone()
	t.Protocols = new(http.Protocols)
	if cfg.UpstreamH2C {
		// Only this: with HTTP/1 also enabled, the transport would use HTTP/1.
		t.Protocols.SetUnencryptedHTTP2(true)
	} else {
		t.Protocols.SetHTTP1(true)
		t.Protocols.SetHTTP2(true)
	}
	return t
}

func (c *Capture) newReverseProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(c.upstream)
			// This proxy is meant to be invisible to the service.
			pr.Out.Host = pr.In.Host
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
		},
		Transport:      transport,
		FlushInterval:  -1,
		ModifyResponse: c.onResponse,
		ErrorHandler:   c.onProxyError,
		// This logger can receive error text naming a URL with its query.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

// exchange is one request and response in raw form. It holds sensitive data,
// and exists only in memory between the request path and sanitizing.
type exchange struct {
	seq       uint64
	start     time.Time
	protoMaj  int
	protoMin  int
	method    string
	path      string
	rawQuery  string
	reqHeader http.Header
	reqTap    *bodyTap

	reqTrailer http.Header
	reqBody    bodyCapture

	response    *http.Response
	status      int
	resHeader   http.Header
	resTrailer  http.Header
	resTap      *bodyTap
	resBody     bodyCapture
	hasResponse bool
	upgraded    bool
	proxyFailed bool

	headersAfter time.Duration
	total        time.Duration
	finished     time.Time
	outcome      traffic.TransportOutcome
}

func (e *exchange) release(budget *memoryBudget) {
	budget.release(e.reqBody.charged)
	budget.release(e.resBody.charged)
	e.reqBody.charged, e.resBody.charged = 0, 0
	e.reqBody.data, e.resBody.data = nil, nil
}

type exchangeKey struct{}

// ServeHTTP forwards a request and records the exchange.
func (c *Capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Registered first, so it runs last: the exchange has been submitted by then.
	c.inflight.Add(1)
	defer c.inflight.Add(-1)
	c.observed.Add(1)
	ex := &exchange{
		seq:       c.seq.Add(1),
		start:     time.Now(),
		protoMaj:  r.ProtoMajor,
		protoMin:  r.ProtoMinor,
		method:    r.Method,
		path:      r.URL.EscapedPath(),
		rawQuery:  r.URL.RawQuery,
		reqHeader: r.Header.Clone(),
	}
	forwarded := r.WithContext(context.WithValue(r.Context(), exchangeKey{}, ex))
	// A zero length means no body, however the server represents it. Over HTTP/2
	// the Body is non-nil, and the proxy correctly never reads it, so a tap would
	// wait for an EOF that never comes.
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		ex.reqTap = newBodyTap(c.limits.MaxRequestBodyBytes, &c.budget)
		forwarded.Body = &teeBody{ReadCloser: r.Body, tap: ex.reqTap}
	}
	defer func() {
		// ReverseProxy panics with http.ErrAbortHandler to abort a response
		// that broke mid-body. Recording must see it, and it must propagate,
		// because that is what shows the client the response was incomplete.
		failure := recover()
		c.finish(ex, r, failure != nil)
		if failure != nil {
			panic(failure)
		}
	}()
	c.proxy.ServeHTTP(w, forwarded)
}

func (c *Capture) onResponse(res *http.Response) error {
	ex, _ := res.Request.Context().Value(exchangeKey{}).(*exchange)
	if ex == nil {
		return nil
	}
	ex.headersAfter = time.Since(ex.start)
	if res.StatusCode == http.StatusSwitchingProtocols {
		// The body is the upgraded connection and must stay unwrapped so the
		// proxy can take it over.
		ex.upgraded = true
		return nil
	}
	ex.hasResponse = true
	ex.response = res
	ex.status = res.StatusCode
	ex.resHeader = res.Header.Clone()
	ex.resTap = newBodyTap(c.limits.MaxResponseBodyBytes, &c.budget)
	res.Body = &teeBody{ReadCloser: res.Body, tap: ex.resTap}
	return nil
}

// onProxyError replies with a plain 502. The error isn't logged or returned to
// the client, because a *url.Error holds the full URL including its query.
func (c *Capture) onProxyError(w http.ResponseWriter, r *http.Request, _ error) {
	if ex, _ := r.Context().Value(exchangeKey{}).(*exchange); ex != nil {
		ex.proxyFailed = true
	}
	w.WriteHeader(http.StatusBadGateway)
}

func (c *Capture) finish(ex *exchange, r *http.Request, aborted bool) {
	ex.total = time.Since(ex.start)
	ex.finished = time.Now()
	if ex.reqTap == nil {
		ex.reqBody.eof = true
	} else {
		ex.reqBody = ex.reqTap.seal()
		// The server fills Trailer before returning EOF, and the tap's mutex
		// orders this read after that write. Without EOF the transport may
		// still be reading, so the map can't be touched.
		if ex.reqBody.eof {
			ex.reqTrailer = r.Trailer.Clone()
		}
	}
	if ex.resTap != nil {
		ex.resBody = ex.resTap.seal()
		// Trailers follow a complete body. Otherwise, as with the request above, the
		// transport may still own this map.
		if ex.resBody.eof {
			ex.resTrailer = ex.response.Trailer.Clone()
		}
	}
	ex.outcome = classifyOutcome(ex, r, aborted)
	if ex.upgraded {
		c.drop(ex, DropUnsupportedProtocol)
		return
	}
	c.submit(ex)
}

func classifyOutcome(ex *exchange, r *http.Request, aborted bool) traffic.TransportOutcome {
	clientGone := r.Context().Err() != nil
	switch {
	case ex.proxyFailed && clientGone:
		return traffic.TransportClientCanceled
	case ex.proxyFailed:
		return traffic.TransportUpstreamError
	case !aborted:
		return traffic.TransportOK
	case !clientGone && ex.resBody.readFailed:
		return traffic.TransportUpstreamAbort
	default:
		return traffic.TransportClientCanceled
	}
}

// submit hands a finished exchange to the workers without ever blocking.
func (c *Capture) submit(ex *exchange) {
	c.submitMu.RLock()
	defer c.submitMu.RUnlock()
	if c.closing {
		c.drop(ex, DropShuttingDown)
		return
	}
	select {
	case c.queue <- ex:
	default:
		c.drop(ex, DropQueueFull)
	}
}

func (c *Capture) drop(ex *exchange, reason DropReason) {
	ex.release(&c.budget)
	c.countDrop(reason, ex.seq)
}

// countDrop logs only the reason and sequence number. Warning once per reason
// keeps a sustained overload from flooding the logs, and Stats has the counts.
func (c *Capture) countDrop(reason DropReason, seq uint64) {
	c.drops[reason].Add(1)
	if c.warned[reason].CompareAndSwap(false, true) {
		c.logger.Warn("dropping recordings", "reason", string(reason))
	}
	c.logger.Debug("recording dropped", "reason", string(reason), "seq", seq)
}

func (c *Capture) process(ex *exchange) {
	defer ex.release(&c.budget)
	// A bug in sanitizing must lose one record, not the process. The panic
	// value is discarded because it could hold traffic content.
	defer func() {
		if recover() != nil {
			c.countDrop(DropSanitizeFailure, ex.seq)
		}
	}()

	select {
	case <-c.abort:
		c.countDrop(DropShutdownDeadline, ex.seq)
		return
	default:
	}
	deadline := ex.finished.Add(c.limits.ProcessingDeadline)
	if time.Now().After(deadline) {
		c.countDrop(DropDeadlineExceeded, ex.seq)
		return
	}

	frame, err := c.encoder.Encode(c.sanitize(ex))
	if err != nil {
		switch {
		case errors.Is(err, traffic.ErrRecordTooLarge):
			c.countDrop(DropRecordTooLarge, ex.seq)
		case errors.Is(err, traffic.ErrInvalidRecord):
			c.countDrop(DropInvalidRecord, ex.seq)
		default:
			c.countDrop(DropEncodeError, ex.seq)
		}
		return
	}

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case c.frames <- frame:
	case <-timer.C:
		c.countDrop(DropDeadlineExceeded, ex.seq)
	case <-c.abort:
		c.countDrop(DropShutdownDeadline, ex.seq)
	}
}

func (c *Capture) writeLoop() {
	ticker := time.NewTicker(c.limits.SyncInterval)
	defer ticker.Stop()
	var backoffUntil time.Time
	for {
		select {
		case frame, ok := <-c.frames:
			if !ok {
				c.closeErr = c.closeWriter()
				return
			}
			if time.Now().Before(backoffUntil) {
				c.countDrop(DropStorageBackoff, 0)
				continue
			}
			if err := c.writer.Append(frame); err != nil {
				backoffUntil = time.Now().Add(c.limits.StorageRetryInterval)
				if errors.Is(err, syscall.ENOSPC) {
					c.countDrop(DropDiskFull, 0)
				} else {
					c.countDrop(DropWriteError, 0)
				}
				continue
			}
			c.persisted.Add(1)
		case <-ticker.C:
			if err := c.writer.Sync(); err != nil {
				c.syncFails.Add(1)
			}
		}
	}
}

func (c *Capture) closeWriter() error {
	defer c.encoder.Close()
	drops := make(map[string]int64)
	for reason, counter := range c.drops {
		if n := counter.Load(); n > 0 {
			drops[string(reason)] = n
		}
	}
	if err := c.writer.CloseWithDrops(drops); err != nil {
		return fmt.Errorf("capture: close traffic writer: %w", err)
	}
	return nil
}

// Close stops recording and drains queued exchanges until ctx ends. It doesn't
// stop the HTTP server, which the caller shuts down first. It then waits for any
// request still being served, because an HTTP/2 server can finish shutting down
// while the handler for a reset stream is still running. It is safe to call more
// than once.
func (c *Capture) Close(ctx context.Context) error {
	c.closeOnce.Do(func() {
		c.waitForHandlers(ctx)
		c.submitMu.Lock()
		c.closing = true
		close(c.queue)
		c.submitMu.Unlock()
	})
	select {
	case <-c.done:
		return c.closeErr
	case <-ctx.Done():
	}
	c.abortOnce.Do(func() { close(c.abort) })

	// Workers now drop what's left without waiting, so this finishes quickly
	// unless a write is stuck in the OS.
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-c.done:
		return errors.Join(ErrShutdownDeadline, c.closeErr)
	case <-timer.C:
		return ErrShutdownDeadline
	}
}

// waitForHandlers returns once no request is being served, or when ctx ends. It polls,
// because a request can begin at any time and a WaitGroup can't be waited on safely
// while that happens.
func (c *Capture) waitForHandlers(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for c.inflight.Load() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Stats returns a snapshot of the counters.
func (c *Capture) Stats() Stats {
	stats := Stats{
		Observed:              c.observed.Load(),
		Persisted:             c.persisted.Load(),
		SyncFailures:          c.syncFails.Load(),
		QueueDepth:            len(c.queue),
		MemoryBudgetUsedBytes: c.budget.used.Load(),
	}
	for reason, counter := range c.drops {
		if n := counter.Load(); n > 0 {
			if stats.Dropped == nil {
				stats.Dropped = make(map[string]int64)
			}
			stats.Dropped[string(reason)] = n
		}
	}
	c.omittedMu.Lock()
	defer c.omittedMu.Unlock()
	if len(c.omitted) > 0 {
		stats.BodiesOmitted = make(map[string]int64, len(c.omitted))
		for reason, n := range c.omitted {
			stats.BodiesOmitted[reason] = n
		}
	}
	return stats
}

func (c *Capture) countOmitted(reason string) {
	c.omittedMu.Lock()
	defer c.omittedMu.Unlock()
	c.omitted[reason]++
}

// sanitizeExchange turns a raw exchange into a record holding only sanitized
// data. This is the only place raw data is read on its way to storage.
func (c *Capture) sanitizeExchange(ex *exchange) *traffic.Record {
	var hits redact.Hits
	engine := c.engine

	requestBody, requestFailed := c.sanitizeBody(redact.RequestBody, ex.reqBody, ex.reqHeader, &hits)
	rec := &traffic.Record{
		SchemaVersion: traffic.SchemaVersion,
		ID:            traffic.NewID(ex.start),
		Seq:           ex.seq,
		CapturedAt:    ex.start.UTC(),
		SessionKey:    engine.SessionKey(ex.reqHeader, ex.rawQuery),
		Protocol:      protocolOf(ex),
		Request: traffic.Request{
			Method:   ex.method,
			Path:     ex.path,
			RawQuery: engine.Query(ex.rawQuery, &hits),
			Headers:  engine.Headers(redact.RequestHeader, ex.reqHeader, &hits),
			Trailers: engine.Headers(redact.RequestTrailer, ex.reqTrailer, &hits),
			Body:     requestBody,
		},
		Timing: traffic.Timing{
			HeadersMicros: ex.headersAfter.Microseconds(),
			TotalMicros:   ex.total.Microseconds(),
		},
		Outcome: traffic.Outcome{Transport: ex.outcome},
	}
	complete := requestBody.State != traffic.BodyOmitted
	replay := replayFromRequest(requestBody, requestFailed)

	if ex.hasResponse {
		responseBody, responseFailed := c.sanitizeBody(redact.ResponseBody, ex.resBody, ex.resHeader, &hits)
		rec.Response = &traffic.Response{
			StatusCode: ex.status,
			Headers:    engine.Headers(redact.ResponseHeader, ex.resHeader, &hits),
			Trailers:   engine.Headers(redact.ResponseTrailer, ex.resTrailer, &hits),
			Body:       responseBody,
		}
		if responseBody.State == traffic.BodyOmitted {
			complete = false
		}
		if responseFailed && replay.Eligible {
			replay = traffic.ReplayInfo{Reason: "response_body_" + responseBody.Reason}
		}
	}
	rec.Replay = replay
	rec.Redaction = traffic.Redaction{
		PolicyDigest: engine.PolicyDigest(),
		Complete:     complete,
		Hits:         hits.List(),
	}
	return rec
}

// replayFromRequest decides whether capture has what it needs to send the
// request again. Whether it is safe to send is decided at replay time.
func replayFromRequest(body traffic.Body, failed bool) traffic.ReplayInfo {
	switch {
	case failed:
		return traffic.ReplayInfo{Reason: "request_body_" + body.Reason}
	case body.State == traffic.BodyPresent, body.State == traffic.BodyEmpty:
		return traffic.ReplayInfo{Eligible: true}
	default:
		return traffic.ReplayInfo{Reason: "request_body_" + body.Reason}
	}
}

func (c *Capture) sanitizeBody(location redact.Location, seen bodyCapture, header http.Header, hits *redact.Hits) (traffic.Body, bool) {
	switch {
	case seen.dropReason != "":
		c.countOmitted(seen.dropReason)
		return traffic.Body{State: traffic.BodyOmitted, Reason: seen.dropReason, ObservedBytes: seen.observed}, false
	case !seen.eof:
		c.countOmitted(ReasonIncomplete)
		return traffic.Body{State: traffic.BodyTruncated, Reason: ReasonIncomplete, ObservedBytes: seen.observed}, false
	}
	result := c.engine.Body(location, redact.BodyInput{
		ContentType:     header.Get("Content-Type"),
		ContentEncoding: strings.Join(header.Values("Content-Encoding"), ","),
		Data:            seen.data,
	}, hits)
	if result.Body.State == traffic.BodyOmitted {
		c.countOmitted(result.Body.Reason)
	}
	return result.Body, result.Failed
}

func protocolOf(ex *exchange) traffic.Protocol {
	switch {
	case ex.protoMaj == 2:
		return traffic.ProtocolHTTP2
	case ex.protoMaj == 1 && ex.protoMin == 0:
		return traffic.ProtocolHTTP10
	default:
		return traffic.ProtocolHTTP11
	}
}
