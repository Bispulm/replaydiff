package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// Role indexes the three targets in RecordResult.Calls.
type Role int

// Roles, in the order calls are stored.
const (
	RoleBaselineA Role = iota
	RoleBaselineB
	RoleCandidate
	roleCount
)

var roleNames = [roleCount]string{"baseline-a", "baseline-b", "candidate"}

func (r Role) String() string { return roleNames[r] }

// CallOutcome says how one upstream call ended. These fixed values stand in for
// error text, which often contains the full URL and its query.
type CallOutcome string

// Call outcomes.
const (
	CallOK               CallOutcome = "ok"
	CallTimeout          CallOutcome = "timeout"
	CallConnectionError  CallOutcome = "connection_error"
	CallCanceled         CallOutcome = "canceled"
	CallResponseTooLarge CallOutcome = "response_too_large"
	CallInvalidRequest   CallOutcome = "invalid_request"
)

// Reasons a record wasn't replayed. A record that capture marked as unreplayable
// is counted under the reason capture recorded.
const (
	SkipMutating            = "mutating_method"
	SkipBodyUnavailable     = "request_body_unavailable"
	SkipUnsupportedProtocol = "unsupported_protocol"
	SkipNotReplayable       = "not_replayable"
)

// CallResult is what one target did with one record.
type CallResult struct {
	Role          string      `json:"role"`
	Outcome       CallOutcome `json:"outcome"`
	Status        int         `json:"status,omitempty"`
	LatencyMicros int64       `json:"latency_us"`
	BodyBytes     int64       `json:"body_bytes"`
	// Header and Body are unsanitized target output. They're for in-process
	// comparison and are deliberately never serialized.
	Header http.Header `json:"-"`
	Body   []byte      `json:"-"`
}

// RecordResult is one logical record's outcome on all targets.
type RecordResult struct {
	ID       string                `json:"id"`
	Seq      uint64                `json:"seq"`
	Method   string                `json:"method"`
	Path     string                `json:"path"`
	RawQuery string                `json:"raw_query,omitempty"`
	Calls    [roleCount]CallResult `json:"calls"`
}

// TargetSummary counts one target's calls.
type TargetSummary struct {
	Calls    int64            `json:"calls"`
	Outcomes map[string]int64 `json:"outcomes,omitempty"`
	Statuses map[string]int64 `json:"statuses,omitempty"`
}

// Summary accounts for every record in a dataset.
type Summary struct {
	Dataset traffic.Integrity `json:"dataset"`
	// CaptureDrops counts exchanges that were never recorded.
	CaptureDrops map[string]int64 `json:"capture_drops,omitempty"`
	// Records is the number of readable records.
	Records int `json:"records"`
	// Skipped counts ineligible records by reason.
	Skipped map[string]int `json:"skipped,omitempty"`
	// Eligible is Records minus Skipped.
	Eligible int `json:"eligible"`
	// Replayed had a call attempted on every target.
	Replayed int `json:"replayed"`
	// NotReplayed were eligible but cut short by interruption.
	NotReplayed int `json:"not_replayed,omitempty"`
	// LoadFailures were eligible but couldn't be read back.
	LoadFailures int `json:"load_failures,omitempty"`
	// RequestsWithRedactedValues were sent without values that were removed at
	// capture, so a target may respond differently than it did to the original.
	RequestsWithRedactedValues int  `json:"requests_with_redacted_values,omitempty"`
	Interrupted                bool `json:"interrupted,omitempty"`

	DurationSeconds float64 `json:"duration_seconds"`
	// RecordsPerSecond counts logical records. UpstreamCallsPerSecond counts
	// real calls, about three per record.
	RecordsPerSecond       float64 `json:"records_per_second"`
	UpstreamCalls          int64   `json:"upstream_calls"`
	UpstreamCallsPerSecond float64 `json:"upstream_calls_per_second"`

	Targets map[string]*TargetSummary `json:"targets"`
}

// Problems lists every reason this run's evidence is incomplete, in a fixed
// order. A failing candidate isn't one of them, because detecting that is the
// point of the run. A failing baseline is, because there is then nothing
// reliable to compare against.
func (s *Summary) Problems() []string {
	var out []string
	for _, problem := range s.Dataset.Problems() {
		out = append(out, "dataset: "+problem)
	}
	if s.Interrupted {
		out = append(out, "the run was interrupted")
	}
	if s.Eligible == 0 {
		out = append(out, "no eligible records to replay")
	}
	if s.NotReplayed > 0 {
		out = append(out, fmt.Sprintf("%d eligible record(s) not replayed", s.NotReplayed))
	}
	if s.LoadFailures > 0 {
		out = append(out, fmt.Sprintf("%d record(s) couldn't be read back", s.LoadFailures))
	}
	for _, role := range []Role{RoleBaselineA, RoleBaselineB} {
		target := s.Targets[role.String()]
		if target == nil {
			continue
		}
		var failed int64
		for outcome, n := range target.Outcomes {
			if outcome != string(CallOK) {
				failed += n
			}
		}
		if failed > 0 {
			out = append(out, fmt.Sprintf("%s: %d failed call(s)", role, failed))
		}
	}
	return out
}

// Complete reports whether the evidence is complete.
func (s *Summary) Complete() bool { return len(s.Problems()) == 0 }

type target struct {
	role      Role
	origin    *url.URL
	headers   http.Header
	client    *http.Client
	transport *http.Transport
	permits   chan struct{}
	limiter   *rate.Limiter
}

// Engine replays datasets. An Engine can run one dataset at a time.
type Engine struct {
	cfg     Config
	targets [roleCount]*target
	methods map[string]bool
	global  chan struct{}
	limiter *rate.Limiter
}

// New validates cfg. No traffic is sent if anything in it is unacceptable.
func New(cfg Config) (*Engine, error) {
	if err := cfg.validateLimits(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	methods, err := allowedMethods(cfg.AllowMethods)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, raw := range cfg.AllowedOrigins {
		origin, _, err := parseOrigin(raw)
		if err != nil {
			return nil, fmt.Errorf("replay: allowed origin: %w", err)
		}
		allowed[origin] = true
	}

	e := &Engine{cfg: cfg, methods: methods, global: make(chan struct{}, cfg.Concurrency)}
	if cfg.RecordsPerSecond > 0 {
		e.limiter = rate.NewLimiter(rate.Limit(cfg.RecordsPerSecond), 1)
	}
	configs := [roleCount]TargetConfig{cfg.BaselineA, cfg.BaselineB, cfg.Candidate}
	seen := make(map[string]Role, roleCount)
	for i, tc := range configs {
		role := Role(i)
		origin, u, err := parseOrigin(tc.URL)
		if err != nil {
			return nil, fmt.Errorf("replay: %s: %w", role, err)
		}
		if !allowed[origin] {
			return nil, &TargetNotAllowedError{Role: role.String(), Origin: origin}
		}
		// Identical targets would compare a service with itself, which always
		// looks clean.
		if other, dup := seen[origin]; dup {
			return nil, fmt.Errorf("replay: %s and %s are the same origin", other, role)
		}
		seen[origin] = role
		if err := validateTargetHeaders(role.String(), tc.Headers); err != nil {
			return nil, err
		}
		e.targets[i] = newTarget(role, u, tc.Headers, cfg)
	}
	return e, nil
}

func newTarget(role Role, origin *url.URL, headers http.Header, cfg Config) *target {
	transport := &http.Transport{
		// Destinations are explicit. An ambient proxy variable mustn't send
		// recorded traffic and credentials somewhere else.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		MaxIdleConns:          cfg.PerTargetConcurrency,
		MaxIdleConnsPerHost:   cfg.PerTargetConcurrency,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	t := &target{
		role:      role,
		origin:    origin,
		headers:   headers,
		transport: transport,
		permits:   make(chan struct{}, cfg.PerTargetConcurrency),
		client: &http.Client{
			Transport: transport,
			// A redirect is a recorded result. Following one could leave the
			// allowlist.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if cfg.TargetCallsPerSecond > 0 {
		t.limiter = rate.NewLimiter(rate.Limit(cfg.TargetCallsPerSecond), 1)
	}
	return t
}

// Close releases idle connections.
func (e *Engine) Close() {
	for _, t := range e.targets {
		t.transport.CloseIdleConnections()
	}
}

// session is one session's eligible records, in arrival order. A session has at
// most one record in flight, which is what preserves its order at every target.
type session struct {
	entries []traffic.Entry
	next    int
}

// collector accumulates results from concurrent workers.
type collector struct {
	mu      sync.Mutex
	summary *Summary
}

func (c *collector) add(update func(*Summary)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	update(c.summary)
}

// Run replays ds. sink, if not nil, receives each result and may be called
// concurrently. Interruption isn't an error: it is reported in the Summary with
// whatever was completed.
func (e *Engine) Run(ctx context.Context, ds *traffic.Dataset, sink func(*RecordResult)) (*Summary, error) {
	summary := &Summary{
		Dataset:      ds.Integrity,
		CaptureDrops: ds.CaptureDrops,
		Records:      len(ds.Entries),
		Targets:      make(map[string]*TargetSummary, roleCount),
	}
	for _, role := range roleNames {
		summary.Targets[role] = &TargetSummary{}
	}
	sessions := e.plan(ds.Entries, summary)
	start := time.Now()
	if len(sessions) > 0 {
		e.schedule(ctx, ds, sessions, &collector{summary: summary}, sink)
	}
	summary.Interrupted = ctx.Err() != nil
	summary.DurationSeconds = time.Since(start).Seconds()
	if summary.DurationSeconds > 0 {
		summary.RecordsPerSecond = float64(summary.Replayed) / summary.DurationSeconds
		summary.UpstreamCallsPerSecond = float64(summary.UpstreamCalls) / summary.DurationSeconds
	}
	return summary, nil
}

// plan applies the eligibility policy and groups records by session. Entries
// are already in arrival order. A record with no session key has nothing to be
// ordered against, so it is a session of its own.
func (e *Engine) plan(entries []traffic.Entry, summary *Summary) []*session {
	var sessions []*session
	byKey := make(map[string]*session)
	for _, entry := range entries {
		if reason := e.skipReason(entry); reason != "" {
			if summary.Skipped == nil {
				summary.Skipped = make(map[string]int)
			}
			summary.Skipped[reason]++
			continue
		}
		summary.Eligible++
		if entry.SessionKey == "" {
			sessions = append(sessions, &session{entries: []traffic.Entry{entry}})
			continue
		}
		s := byKey[entry.SessionKey]
		if s == nil {
			s = &session{}
			byKey[entry.SessionKey] = s
			sessions = append(sessions, s)
		}
		s.entries = append(s.entries, entry)
	}
	return sessions
}

func (e *Engine) skipReason(entry traffic.Entry) string {
	switch {
	case !entry.Replay.Eligible:
		if entry.Replay.Reason != "" {
			return entry.Replay.Reason
		}
		return SkipNotReplayable
	case entry.Protocol == traffic.ProtocolGRPC:
		return SkipUnsupportedProtocol
	case !e.methods[strings.ToUpper(entry.Method)]:
		return SkipMutating
	case entry.BodyState != traffic.BodyPresent && entry.BodyState != traffic.BodyEmpty:
		return SkipBodyUnavailable
	}
	return ""
}

// schedule runs sessions round-robin. ready is a FIFO of sessions with work
// left. A worker takes the session at the front, runs one record, and puts the
// session at the back, so a long session gets the same turns as a short one and
// a slow one holds only one worker. ready's capacity is the active session
// limit, and no more sessions than that exist at once, so sends never block.
func (e *Engine) schedule(ctx context.Context, ds *traffic.Dataset, sessions []*session, stats *collector, sink func(*RecordResult)) {
	active := min(e.cfg.MaxActiveSessions, len(sessions))
	ready := make(chan *session, active)
	for _, s := range sessions[:active] {
		ready <- s
	}
	pending := sessions[active:]

	var mu sync.Mutex
	finishSession := func() {
		mu.Lock()
		defer mu.Unlock()
		if len(pending) > 0 {
			ready <- pending[0]
			pending = pending[1:]
			return
		}
		active--
		if active == 0 {
			close(ready)
		}
	}

	// Each record makes three calls, so more workers than this would only hold
	// loaded records while waiting for call permits.
	workers := max(1, (e.cfg.Concurrency+int(roleCount)-1)/int(roleCount))
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for s := range ready {
				if ctx.Err() != nil {
					remaining := len(s.entries) - s.next
					stats.add(func(sum *Summary) { sum.NotReplayed += remaining })
					finishSession()
					continue
				}
				e.replayRecord(ctx, ds, s.entries[s.next], stats, sink)
				s.next++
				if s.next < len(s.entries) {
					ready <- s
				} else {
					finishSession()
				}
			}
		})
	}
	wg.Wait()
}

func (e *Engine) replayRecord(ctx context.Context, ds *traffic.Dataset, entry traffic.Entry, stats *collector, sink func(*RecordResult)) {
	if e.limiter != nil {
		if err := e.limiter.Wait(ctx); err != nil {
			stats.add(func(sum *Summary) { sum.NotReplayed++ })
			return
		}
	}
	rec, err := ds.Load(entry)
	if err != nil {
		stats.add(func(sum *Summary) { sum.LoadFailures++ })
		return
	}

	result := &RecordResult{
		ID:       rec.ID,
		Seq:      rec.Seq,
		Method:   rec.Request.Method,
		Path:     rec.Request.Path,
		RawQuery: rec.Request.RawQuery,
	}
	var wg sync.WaitGroup
	for i, t := range e.targets {
		wg.Go(func() { result.Calls[i] = e.call(ctx, t, rec) })
	}
	wg.Wait()

	stats.add(func(sum *Summary) {
		attempted := true
		for i := range result.Calls {
			call := &result.Calls[i]
			if call.Outcome == CallCanceled {
				attempted = false
			}
			target := sum.Targets[call.Role]
			target.Calls++
			target.Outcomes = increment(target.Outcomes, string(call.Outcome))
			if call.Status != 0 {
				target.Statuses = increment(target.Statuses, fmt.Sprintf("%dxx", call.Status/100))
			}
			sum.UpstreamCalls++
		}
		if attempted {
			sum.Replayed++
		} else {
			sum.NotReplayed++
		}
		if hasRedactedRequestValue(rec) {
			sum.RequestsWithRedactedValues++
		}
	})
	if sink != nil {
		sink(result)
	}
}

func increment(counts map[string]int64, key string) map[string]int64 {
	if counts == nil {
		counts = make(map[string]int64)
	}
	counts[key]++
	return counts
}

func hasRedactedRequestValue(rec *traffic.Record) bool {
	return slices.ContainsFunc(rec.Redaction.Hits, func(hit traffic.RedactionHit) bool {
		return strings.HasPrefix(hit.Location, "request.")
	})
}

// call makes exactly one attempt. The per-target permit is taken first, so a
// saturated target doesn't sit on global permits other targets could be using.
func (e *Engine) call(ctx context.Context, t *target, rec *traffic.Record) CallResult {
	result := CallResult{Role: t.role.String()}
	select {
	case t.permits <- struct{}{}:
		defer func() { <-t.permits }()
	case <-ctx.Done():
		result.Outcome = CallCanceled
		return result
	}
	select {
	case e.global <- struct{}{}:
		defer func() { <-e.global }()
	case <-ctx.Done():
		result.Outcome = CallCanceled
		return result
	}
	if t.limiter != nil {
		if err := t.limiter.Wait(ctx); err != nil {
			result.Outcome = CallCanceled
			return result
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	req, err := buildRequest(callCtx, t, rec)
	if err != nil {
		result.Outcome = CallInvalidRequest
		return result
	}

	start := time.Now()
	resp, err := t.client.Do(req)
	if err != nil {
		result.LatencyMicros = time.Since(start).Microseconds()
		result.Outcome = classifyError(ctx, callCtx, err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, e.cfg.MaxResponseBytes+1))
	result.LatencyMicros = time.Since(start).Microseconds()
	result.Status = resp.StatusCode
	result.BodyBytes = int64(len(body))
	switch {
	case err != nil:
		result.Outcome = classifyError(ctx, callCtx, err)
	case int64(len(body)) > e.cfg.MaxResponseBytes:
		result.Outcome = CallResponseTooLarge
	default:
		result.Outcome = CallOK
		result.Header = resp.Header
		result.Body = body
	}
	return result
}

func classifyError(ctx, callCtx context.Context, err error) CallOutcome {
	switch {
	case ctx.Err() != nil:
		return CallCanceled
	case errors.Is(callCtx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return CallTimeout
	default:
		return CallConnectionError
	}
}

// droppedHeaders are never sent. They're connection-specific, derived from the
// original bytes, or describe the original route. Accept-Encoding is left to
// the transport, which decompresses transparently so that responses compare
// equal whatever their wire encoding was.
var droppedHeaders = map[string]bool{
	"Accept-Encoding":     true,
	"Connection":          true,
	"Content-Encoding":    true,
	"Content-Length":      true,
	"Expect":              true,
	"Forwarded":           true,
	"Host":                true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"X-Forwarded-For":     true,
	"X-Forwarded-Host":    true,
	"X-Forwarded-Port":    true,
	"X-Forwarded-Proto":   true,
	"X-Real-Ip":           true,
}

// buildRequest assembles a call from the target's origin and the record's path
// and query. The URL is set field by field rather than parsed from a joined
// string, so no record content can change the scheme or host.
func buildRequest(ctx context.Context, t *target, rec *traffic.Record) (*http.Request, error) {
	var body io.Reader = http.NoBody
	if len(rec.Request.Body.Data) > 0 {
		body = bytes.NewReader(rec.Request.Body.Data)
	}
	req, err := http.NewRequestWithContext(ctx, rec.Request.Method, t.origin.String(), body)
	if err != nil {
		return nil, fmt.Errorf("replay: build request: %w", err)
	}
	if rec.Request.Path == "*" {
		req.URL.Opaque = "*"
	} else {
		decoded, err := url.PathUnescape(rec.Request.Path)
		if err != nil {
			return nil, fmt.Errorf("replay: invalid path escape: %w", err)
		}
		req.URL.Path = decoded
		req.URL.RawPath = rec.Request.Path
	}
	req.URL.RawQuery = rec.Request.RawQuery
	req.Host = t.origin.Host

	// Without this the client sends its own default, which the original
	// request didn't have.
	req.Header["User-Agent"] = []string{""}
	for name, values := range rec.Request.Headers {
		canonical := http.CanonicalHeaderKey(name)
		// A placeholder isn't a value. Sending it could look like a real but
		// wrong credential, and the header's absence is the honest signal.
		if droppedHeaders[canonical] || slices.Contains(values, redact.Placeholder) {
			continue
		}
		req.Header[canonical] = slices.Clone(values)
	}
	for name, values := range t.headers {
		req.Header[http.CanonicalHeaderKey(name)] = slices.Clone(values)
	}
	return req, nil
}
