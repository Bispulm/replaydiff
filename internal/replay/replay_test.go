package replay

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// spec describes a record to write into a test dataset.
type spec struct {
	session string
	method  string
	path    string
	query   string
	headers map[string][]string
	body    traffic.Body
	replay  *traffic.ReplayInfo
	hits    []traffic.RedactionHit

	protocol   traffic.Protocol
	rpc        string
	descriptor string
}

func writeDataset(t *testing.T, specs []spec) string {
	t.Helper()
	dir := t.TempDir()
	enc, err := traffic.NewEncoder(traffic.EncoderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	w, err := traffic.NewWriter(dir, traffic.WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range specs {
		rec := &traffic.Record{
			SchemaVersion: traffic.SchemaVersion,
			ID:            fmt.Sprintf("rec-%06d", i+1),
			Seq:           uint64(i + 1),
			CapturedAt:    time.Date(2026, 11, 5, 12, 0, i, 0, time.UTC),
			SessionKey:    s.session,
			Protocol:      cmp.Or(s.protocol, traffic.ProtocolHTTP11),
			Request: traffic.Request{
				Method:   cmpOr(s.method, http.MethodGet),
				Path:     cmpOr(s.path, "/"),
				RawQuery: s.query,
				Headers:  s.headers,
				Body:     s.body,
			},
			RPC:       s.rpc,
			Outcome:   traffic.Outcome{Transport: traffic.TransportOK},
			Redaction: traffic.Redaction{Complete: true, Hits: s.hits},
			Replay:    traffic.ReplayInfo{Eligible: true},
		}
		if s.descriptor != "" {
			rec.Descriptor = &traffic.DescriptorRef{SetDigest: s.descriptor}
		}
		if rec.Request.Body.State == "" {
			rec.Request.Body.State = traffic.BodyEmpty
		}
		if s.replay != nil {
			rec.Replay = *s.replay
		}
		frame, err := enc.Encode(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Append(frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func scan(t *testing.T, dir string) *traffic.Dataset {
	t.Helper()
	ds, err := traffic.Scan(dir, traffic.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ds.Close() })
	return ds
}

// observedRequest is what a target actually received.
type observedRequest struct {
	Method string
	Path   string
	Query  string
	Host   string
	Body   string
	Header http.Header

	ProtoMajor    int
	ContentLength int64
}

// fakeTarget is a real local HTTP server recording what reaches it.
type fakeTarget struct {
	*httptest.Server
	mu       sync.Mutex
	requests []observedRequest
	handler  http.HandlerFunc
}

func newFakeTarget(t *testing.T, handler http.HandlerFunc) *fakeTarget {
	t.Helper()
	target := &fakeTarget{handler: handler}
	target.Server = httptest.NewServer(target.record())
	t.Cleanup(target.Close)
	return target
}

// record returns the handler that notes each request before calling the test's.
func (f *fakeTarget) record() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, observedRequest{
			Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Host: r.Host, Body: string(body), Header: r.Header.Clone(),
			ProtoMajor: r.ProtoMajor, ContentLength: r.ContentLength,
		})
		f.mu.Unlock()
		if f.handler != nil {
			f.handler(w, r)
		}
	})
}

func (f *fakeTarget) seen() []observedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

type cluster struct{ a, b, c *fakeTarget }

func newCluster(t *testing.T, handler http.HandlerFunc) cluster {
	t.Helper()
	return cluster{newFakeTarget(t, handler), newFakeTarget(t, handler), newFakeTarget(t, handler)}
}

func (c cluster) config() Config {
	return Config{
		BaselineA:      TargetConfig{URL: c.a.URL},
		BaselineB:      TargetConfig{URL: c.b.URL},
		Candidate:      TargetConfig{URL: c.c.URL},
		AllowedOrigins: []string{c.a.URL, c.b.URL, c.c.URL},
	}
}

func mustEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	engine, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return engine
}

func mustRun(t *testing.T, engine *Engine, ds *traffic.Dataset) (*Summary, []*RecordResult) {
	t.Helper()
	var (
		mu      sync.Mutex
		results []*RecordResult
	)
	summary, err := engine.Run(context.Background(), ds, func(r *RecordResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
	})
	if err != nil {
		t.Fatal(err)
	}
	return summary, results
}

func TestRefusesTargetsNotOnTheAllowlist(t *testing.T) {
	c := newCluster(t, nil)
	for name, adjust := range map[string]func(*Config){
		"baseline a": func(cfg *Config) { cfg.AllowedOrigins = []string{c.b.URL, c.c.URL} },
		"baseline b": func(cfg *Config) { cfg.AllowedOrigins = []string{c.a.URL, c.c.URL} },
		"candidate":  func(cfg *Config) { cfg.AllowedOrigins = []string{c.a.URL, c.b.URL} },
		"empty":      func(cfg *Config) { cfg.AllowedOrigins = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := c.config()
			adjust(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestRejectsInvalidTargetsAndLimits(t *testing.T) {
	c := newCluster(t, nil)
	for name, adjust := range map[string]func(*Config){
		"path in url":        func(cfg *Config) { cfg.Candidate.URL = c.c.URL + "/prefix" },
		"query in url":       func(cfg *Config) { cfg.Candidate.URL = c.c.URL + "?a=1" },
		"credentials in url": func(cfg *Config) { cfg.Candidate.URL = "http://u:p@" + strings.TrimPrefix(c.c.URL, "http://") },
		"bad scheme":         func(cfg *Config) { cfg.Candidate.URL = "ftp://example.test" },
		"no host":            func(cfg *Config) { cfg.Candidate.URL = "http://" },
		"empty":              func(cfg *Config) { cfg.Candidate.URL = "" },
		"baselines identical": func(cfg *Config) {
			cfg.BaselineB.URL = cfg.BaselineA.URL
		},
		"candidate is a baseline": func(cfg *Config) { cfg.Candidate.URL = cfg.BaselineA.URL },
		"bad allowlist entry":     func(cfg *Config) { cfg.AllowedOrigins = append(cfg.AllowedOrigins, "::nope") },
		"connect allowed":         func(cfg *Config) { cfg.AllowMethods = []string{"CONNECT"} },
		"trace allowed":           func(cfg *Config) { cfg.AllowMethods = []string{"trace"} },
		"negative rate":           func(cfg *Config) { cfg.RecordsPerSecond = -1 },
		"rate not a number":       func(cfg *Config) { cfg.RecordsPerSecond = math.NaN() },
		"infinite rate":           func(cfg *Config) { cfg.TargetCallsPerSecond = math.Inf(1) },
		"invalid header name":     func(cfg *Config) { cfg.Candidate.Headers = http.Header{"Bad Name": {"x"}} },
		"header with newline":     func(cfg *Config) { cfg.Candidate.Headers = http.Header{"X-A": {"a\nb"}} },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := c.config()
			adjust(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestAllowlistMatchesNormalizedOrigins(t *testing.T) {
	cfg := Config{
		BaselineA:      TargetConfig{URL: "http://A.example.test:80"},
		BaselineB:      TargetConfig{URL: "https://b.example.test:443/"},
		Candidate:      TargetConfig{URL: "http://c.example.test:8080"},
		AllowedOrigins: []string{"http://a.example.test", "https://B.example.test", "http://c.example.test:8080"},
	}
	engine, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.Close()

	cfg.Candidate.URL = "http://c.example.test:9090"
	if _, err := New(cfg); err == nil {
		t.Fatal("a different port is a different origin")
	}
	cfg.Candidate.URL = "https://c.example.test:8080"
	if _, err := New(cfg); err == nil {
		t.Fatal("a different scheme is a different origin")
	}
}

func TestReplaysEligibleRecordsToEveryTarget(t *testing.T) {
	c := newCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reply")
	})
	dir := writeDataset(t, []spec{{
		path:    "/v1/items/a%2Fb",
		query:   "x=1&token=REDACTED",
		headers: map[string][]string{"Accept": {"application/json"}},
	}})
	summary, results := mustRun(t, mustEngine(t, c.config()), scan(t, dir))

	for name, target := range map[string]*fakeTarget{"a": c.a, "b": c.b, "c": c.c} {
		seen := target.seen()
		if len(seen) != 1 {
			t.Fatalf("%s saw %d requests", name, len(seen))
		}
		if seen[0].Path != "/v1/items/a%2Fb" || seen[0].Query != "x=1&token=REDACTED" || seen[0].Header.Get("Accept") != "application/json" {
			t.Fatalf("%s saw %+v", name, seen[0])
		}
	}
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	for _, call := range results[0].Calls {
		if call.Outcome != CallOK || call.Status != http.StatusOK || call.BodyBytes != 5 || string(call.Body) != "reply" {
			t.Fatalf("call = %+v", call)
		}
	}
	if summary.Records != 1 || summary.Eligible != 1 || summary.Replayed != 1 || !summary.Complete() {
		t.Fatalf("summary = %+v, problems = %v", summary, summary.Problems())
	}
	if summary.Targets["candidate"].Calls != 1 || summary.Targets["baseline-a"].Statuses["2xx"] != 1 {
		t.Fatalf("targets = %+v", summary.Targets)
	}
}

func TestRequestBodyIsSentWithACorrectLength(t *testing.T) {
	c := newCluster(t, nil)
	stored := []byte(`{"sku":"a","email":"[REDACTED]"}`)
	dir := writeDataset(t, []spec{{
		method:  http.MethodPost,
		headers: map[string][]string{"Content-Type": {"application/json"}},
		body:    traffic.Body{State: traffic.BodyPresent, Data: stored, OriginalEncoding: "gzip"},
	}})
	cfg := c.config()
	cfg.AllowMethods = []string{http.MethodPost}
	mustRun(t, mustEngine(t, cfg), scan(t, dir))

	seen := c.c.seen()
	if len(seen) != 1 || seen[0].Body != string(stored) {
		t.Fatalf("seen = %+v", seen)
	}
	if got := seen[0].Header.Get("Content-Length"); got != fmt.Sprint(len(stored)) {
		t.Fatalf("Content-Length = %q", got)
	}
	if got := seen[0].Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, but the stored body is decompressed", got)
	}
}

// Nothing in a record can choose where a request goes.
func TestCapturedDataCannotSelectADestination(t *testing.T) {
	var evilHits atomic.Int64
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilHits.Add(1) }))
	defer evil.Close()
	evilHost := strings.TrimPrefix(evil.URL, "http://")

	c := newCluster(t, nil)
	dir := writeDataset(t, []spec{
		{path: "//" + evilHost + "/x", headers: map[string][]string{"Host": {evilHost}, "X-Forwarded-Host": {evilHost}, "Forwarded": {"host=" + evilHost}}},
		{path: "/@" + evilHost + "/y"},
	})
	mustRun(t, mustEngine(t, c.config()), scan(t, dir))

	if n := evilHits.Load(); n != 0 {
		t.Fatalf("%d requests reached a host named by the record", n)
	}
	seen := c.c.seen()
	if len(seen) != 2 {
		t.Fatalf("candidate saw %d requests", len(seen))
	}
	want := strings.TrimPrefix(c.c.URL, "http://")
	for _, req := range seen {
		if req.Host != want {
			t.Errorf("Host = %q, want %q", req.Host, want)
		}
		if req.Header.Get("X-Forwarded-Host") != "" || req.Header.Get("Forwarded") != "" {
			t.Errorf("forwarding headers replayed: %v", req.Header)
		}
	}
}

func TestRedirectsAreRecordedAndNotFollowed(t *testing.T) {
	var followed atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }))
	defer elsewhere.Close()
	c := newCluster(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/next", http.StatusFound)
	})
	summary, results := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, []spec{{path: "/start"}})))
	if n := followed.Load(); n != 0 {
		t.Fatalf("redirect followed %d times", n)
	}
	if got := results[0].Calls[RoleCandidate].Status; got != http.StatusFound {
		t.Fatalf("status = %d", got)
	}
	if summary.Targets["candidate"].Statuses["3xx"] != 1 {
		t.Fatalf("targets = %+v", summary.Targets)
	}
}

func TestMutatingRequestsAreSkippedByDefaultAndCounted(t *testing.T) {
	c := newCluster(t, nil)
	specs := []spec{
		{method: http.MethodGet, path: "/read"},
		{method: http.MethodHead, path: "/read"},
		{method: http.MethodOptions, path: "/read"},
		{method: http.MethodPost, path: "/write"},
		{method: http.MethodPut, path: "/write"},
		{method: http.MethodPatch, path: "/write"},
		{method: http.MethodDelete, path: "/write"},
	}
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, specs)))
	for _, req := range c.c.seen() {
		if req.Path == "/write" {
			t.Fatalf("mutating request reached the candidate: %+v", req)
		}
	}
	if summary.Skipped[SkipMutating] != 4 || summary.Eligible != 3 || summary.Replayed != 3 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestMutatingMethodRequiresExplicitOptIn(t *testing.T) {
	c := newCluster(t, nil)
	cfg := c.config()
	cfg.AllowMethods = []string{"post"}
	specs := []spec{{method: http.MethodPost, path: "/allowed"}, {method: http.MethodDelete, path: "/denied"}}
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))
	seen := c.a.seen()
	if len(seen) != 1 || seen[0].Path != "/allowed" {
		t.Fatalf("seen = %+v", seen)
	}
	if summary.Skipped[SkipMutating] != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

// HTTP methods are case-sensitive, so "get" is not GET. A lenient server might
// treat either spelling as whatever it likes, which a safety check can't assume.
func TestMethodCaseIsNotNormalizedForEligibility(t *testing.T) {
	c := newCluster(t, nil)
	specs := []spec{{method: "get", path: "/lower"}, {method: "GeT", path: "/mixed"}}
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, specs)))
	if len(c.a.seen()) != 0 || summary.Skipped[SkipMutating] != 2 {
		t.Fatalf("seen = %v, summary = %+v", c.a.seen(), summary)
	}
}

func TestRecordsCaptureMarkedUnreplayableAreSkippedWithTheirReason(t *testing.T) {
	c := newCluster(t, nil)
	specs := []spec{
		{path: "/ok"},
		{path: "/omitted", replay: &traffic.ReplayInfo{Reason: "request_body_malformed_json"}},
		{path: "/big", replay: &traffic.ReplayInfo{Reason: "request_body_body_too_large"}},
	}
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, specs)))
	if len(c.a.seen()) != 1 {
		t.Fatalf("seen = %+v", c.a.seen())
	}
	if summary.Skipped["request_body_malformed_json"] != 1 || summary.Skipped["request_body_body_too_large"] != 1 {
		t.Fatalf("skipped = %+v", summary.Skipped)
	}
}

// Files can be handcrafted, so an eligible flag isn't believed on its own. A
// record with no stored body must not be sent as if its body were empty.
func TestRecordClaimingEligibilityWithoutABodyIsNotSent(t *testing.T) {
	c := newCluster(t, nil)
	specs := []spec{{path: "/forged", body: traffic.Body{State: traffic.BodyOmitted, Reason: "x"}}}
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, specs)))
	if len(c.a.seen()) != 0 || summary.Skipped[SkipBodyUnavailable] != 1 {
		t.Fatalf("seen = %v, summary = %+v", c.a.seen(), summary)
	}
}

// gRPC runs over HTTP POST whatever the RPC does, so allowing POST must not
// make gRPC traffic eligible.
func TestGRPCIsNotReplayedByAllowingPost(t *testing.T) {
	c := newCluster(t, nil)
	cfg := c.config()
	cfg.AllowMethods = []string{http.MethodPost}
	specs := []spec{{method: http.MethodPost, path: "/orders.v1.Orders/Delete", rpc: "/orders.v1.Orders/Delete", protocol: traffic.ProtocolGRPC}}
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))
	if len(c.a.seen()) != 0 || summary.Skipped[SkipRPCNotAllowed] != 1 {
		t.Fatalf("seen = %v, summary = %+v", c.a.seen(), summary)
	}
}

func TestZeroEligibleRecordsIsNeverComplete(t *testing.T) {
	c := newCluster(t, nil)
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, []spec{{method: http.MethodPost}})))
	if summary.Complete() {
		t.Fatalf("summary = %+v", summary)
	}
	if !strings.Contains(strings.Join(summary.Problems(), ";"), "no eligible") {
		t.Fatalf("problems = %v", summary.Problems())
	}
}

func TestPlaceholderHeadersAreNeverSent(t *testing.T) {
	c := newCluster(t, nil)
	dir := writeDataset(t, []spec{{headers: map[string][]string{
		"Authorization": {redact.Placeholder},
		"Cookie":        {redact.Placeholder},
		"X-Custom":      {redact.Placeholder},
		"Accept":        {"*/*"},
	}}})
	mustRun(t, mustEngine(t, c.config()), scan(t, dir))
	got := c.c.seen()[0].Header
	for _, name := range []string{"Authorization", "Cookie", "X-Custom"} {
		if got.Get(name) != "" {
			t.Errorf("%s was sent: %q", name, got.Get(name))
		}
	}
	if got.Get("Accept") != "*/*" {
		t.Errorf("Accept = %q", got.Get("Accept"))
	}
}

func TestPerTargetCredentialsAreAppliedAndNeverReported(t *testing.T) {
	c := newCluster(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") })
	cfg := c.config()
	cfg.BaselineA.Headers = http.Header{"Authorization": {"Bearer credential-for-a"}}
	cfg.BaselineB.Headers = http.Header{"Authorization": {"Bearer credential-for-b"}}
	cfg.Candidate.Headers = http.Header{"Authorization": {"Bearer credential-for-c"}}
	dir := writeDataset(t, []spec{{headers: map[string][]string{"Authorization": {redact.Placeholder}}}})
	summary, results := mustRun(t, mustEngine(t, cfg), scan(t, dir))

	for target, want := range map[*fakeTarget]string{c.a: "a", c.b: "b", c.c: "c"} {
		if got := target.seen()[0].Header.Get("Authorization"); got != "Bearer credential-for-"+want {
			t.Errorf("target %s got %q", want, got)
		}
	}
	data, err := json.Marshal([]any{summary, results})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("credential-for")) {
		t.Fatalf("credential in results: %s", data)
	}
}

func TestReplayFidelityGapsAreCounted(t *testing.T) {
	c := newCluster(t, nil)
	dir := writeDataset(t, []spec{
		{path: "/a", hits: []traffic.RedactionHit{{Location: string(redact.RequestBody), Rule: "$.email", Count: 1}}},
		{path: "/b", hits: []traffic.RedactionHit{{Location: string(redact.ResponseBody), Rule: "$.email", Count: 1}}},
	})
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, dir))
	if summary.RequestsWithRedactedValues != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

// Arrival order alone can't catch overlapping requests, since an earlier step
// that started first still arrives first. So each target also checks that the
// previous step has finished before the next one arrives.
func TestSessionOrderIsPreservedAtEveryTarget(t *testing.T) {
	const sessions, steps = 3, 15
	var specs []spec
	for step := range steps {
		for s := range sessions {
			specs = append(specs, spec{session: fmt.Sprintf("%032x", s+1), path: fmt.Sprintf("/s/%d/%d", s, step)})
		}
	}
	type progress struct {
		mu        sync.Mutex
		finished  map[int]int
		violation string
	}
	checked := func(name string) (*progress, http.HandlerFunc) {
		state := &progress{finished: make(map[int]int)}
		return state, func(_ http.ResponseWriter, r *http.Request) {
			var session, step int
			if _, err := fmt.Sscanf(r.URL.Path, "/s/%d/%d", &session, &step); err != nil {
				return
			}
			state.mu.Lock()
			if state.finished[session] != step && state.violation == "" {
				state.violation = fmt.Sprintf("%s session %d: step %d arrived after only %d steps finished", name, session, step, state.finished[session])
			}
			state.mu.Unlock()
			time.Sleep(time.Duration(1+rand.IntN(4)) * time.Millisecond)
			state.mu.Lock()
			state.finished[session]++
			state.mu.Unlock()
		}
	}
	c := newCluster(t, nil)
	stateA, handlerA := checked("baseline-a")
	stateB, handlerB := checked("baseline-b")
	stateC, handlerC := checked("candidate")
	c.a.handler, c.b.handler, c.c.handler = handlerA, handlerB, handlerC

	cfg := c.config()
	// Enough capacity that nothing but session ordering keeps steps apart.
	cfg.Concurrency = 90
	cfg.PerTargetConcurrency = 30
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))
	if summary.Replayed != sessions*steps {
		t.Fatalf("replayed = %d", summary.Replayed)
	}
	for _, state := range []*progress{stateA, stateB, stateC} {
		if state.violation != "" {
			t.Fatal(state.violation)
		}
	}
}

// With one record in flight at a time, round-robin must alternate strictly, so
// a long session can't run to completion before another gets a turn.
func TestSessionsTakeTurnsFairly(t *testing.T) {
	sessionA, sessionB, sessionC := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	var specs []spec
	for i := range 6 {
		specs = append(specs, spec{session: sessionA, path: fmt.Sprintf("/a/%d", i)})
	}
	for i := range 6 {
		specs = append(specs, spec{session: sessionB, path: fmt.Sprintf("/b/%d", i)})
	}
	for i := range 6 {
		specs = append(specs, spec{session: sessionC, path: fmt.Sprintf("/c/%d", i)})
	}
	c := newCluster(t, nil)
	cfg := c.config()
	cfg.Concurrency = 3 // Three calls per record, so one record at a time.
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))

	var got []string
	for _, req := range c.a.seen() {
		got = append(got, req.Path[1:2])
	}
	want := strings.Split(strings.Repeat("abc", 6), "")
	if !slices.Equal(got, want) {
		t.Fatalf("service order = %v, want strict alternation", got)
	}
}

func TestSlowSessionDoesNotDelayOtherSessions(t *testing.T) {
	slowSession := strings.Repeat("a", 32)
	var specs []spec
	for i := range 4 {
		specs = append(specs, spec{session: slowSession, path: fmt.Sprintf("/slow/%d", i)})
	}
	for i := range 20 {
		specs = append(specs, spec{session: fmt.Sprintf("%032x", i+1), path: "/fast"})
	}
	var fastDone atomic.Int64
	var fastDoneWhenSlowFinished atomic.Int64
	c := newCluster(t, func(_ http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/slow/") {
			time.Sleep(100 * time.Millisecond)
		}
	})
	cfg := c.config()
	cfg.Concurrency = 6 // Two records at a time.
	engine := mustEngine(t, cfg)
	_, err := engine.Run(context.Background(), scan(t, writeDataset(t, specs)), func(r *RecordResult) {
		if r.Path == "/fast" {
			fastDone.Add(1)
		}
		if r.Path == "/slow/3" {
			fastDoneWhenSlowFinished.Store(fastDone.Load())
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := fastDoneWhenSlowFinished.Load(); got != 20 {
		t.Fatalf("only %d of 20 fast sessions finished before the slow session did", got)
	}
}

func TestActiveSessionsAreBounded(t *testing.T) {
	var specs []spec
	for s := range 12 {
		for step := range 3 {
			specs = append(specs, spec{session: fmt.Sprintf("%032x", s+1), path: fmt.Sprintf("/s/%d/%d", s, step)})
		}
	}
	var (
		mu      sync.Mutex
		started = make(map[int]int)
		active  int
		peak    int
	)
	c := newCluster(t, nil)
	c.a.handler = func(_ http.ResponseWriter, r *http.Request) {
		var s, step int
		if _, err := fmt.Sscanf(r.URL.Path, "/s/%d/%d", &s, &step); err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		started[s]++
		if started[s] == 1 {
			active++
			peak = max(peak, active)
		}
		if started[s] == 3 {
			active--
		}
	}
	cfg := c.config()
	cfg.MaxActiveSessions = 2
	cfg.Concurrency = 30
	cfg.PerTargetConcurrency = 10
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))
	if summary.Replayed != 36 {
		t.Fatalf("replayed = %d", summary.Replayed)
	}
	if peak > 2 {
		t.Fatalf("peak active sessions = %d, limit 2", peak)
	}
}

func TestSessionlessRecordsRunIndependently(t *testing.T) {
	const records = 8
	release := make(chan struct{})
	var arrived atomic.Int64
	c := newCluster(t, nil)
	c.a.handler = func(_ http.ResponseWriter, _ *http.Request) {
		if arrived.Add(1) == records {
			close(release)
		}
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}
	cfg := c.config()
	cfg.Concurrency = 3 * records
	cfg.PerTargetConcurrency = records
	specs := make([]spec, records)
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))
	if arrived.Load() != records {
		t.Fatalf("arrived = %d", arrived.Load())
	}
	select {
	case <-release:
	default:
		t.Fatal("records without a session must run concurrently")
	}
}

// peakTracker measures the highest number of handlers running at once.
type peakTracker struct{ current, peak atomic.Int64 }

func (p *peakTracker) enter() {
	now := p.current.Add(1)
	for seen := p.peak.Load(); now > seen && !p.peak.CompareAndSwap(seen, now); seen = p.peak.Load() {
	}
}

func (p *peakTracker) leave() { p.current.Add(-1) }

// The global limit is ample here, so only the per-target limit can hold this.
func TestPerTargetConcurrencyLimitHolds(t *testing.T) {
	c := newCluster(t, nil)
	var peaks [3]peakTracker
	for i, target := range []*fakeTarget{c.a, c.b, c.c} {
		target.handler = func(_ http.ResponseWriter, _ *http.Request) {
			peaks[i].enter()
			defer peaks[i].leave()
			time.Sleep(5 * time.Millisecond)
		}
	}
	cfg := c.config()
	cfg.Concurrency = 60
	cfg.PerTargetConcurrency = 3
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, make([]spec, 40))))
	for i := range peaks {
		if got := peaks[i].peak.Load(); got == 0 || got > 3 {
			t.Errorf("target %d peak = %d, want between 1 and 3", i, got)
		}
	}
}

// The per-target limit is ample here, so only the global limit can hold this.
func TestGlobalConcurrencyLimitHolds(t *testing.T) {
	c := newCluster(t, nil)
	var peak peakTracker
	handler := func(_ http.ResponseWriter, _ *http.Request) {
		peak.enter()
		defer peak.leave()
		time.Sleep(5 * time.Millisecond)
	}
	c.a.handler, c.b.handler, c.c.handler = handler, handler, handler
	cfg := c.config()
	cfg.Concurrency = 7
	cfg.PerTargetConcurrency = 7
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, make([]spec, 40))))
	if got := peak.peak.Load(); got == 0 || got > 7 {
		t.Fatalf("global peak = %d, want between 1 and 7", got)
	}
}

func TestRecordRateLimitCountsLogicalRecordsAndReportsBothRates(t *testing.T) {
	c := newCluster(t, nil)
	cfg := c.config()
	cfg.RecordsPerSecond = 50
	start := time.Now()
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, make([]spec, 10))))
	elapsed := time.Since(start)
	// Ten records at 50/s take at least nine intervals of 20ms.
	if elapsed < 170*time.Millisecond {
		t.Fatalf("elapsed = %v, want at least 170ms", elapsed)
	}
	if summary.UpstreamCalls != 30 || summary.Replayed != 10 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.UpstreamCallsPerSecond <= summary.RecordsPerSecond {
		t.Fatalf("rates: records %v, calls %v", summary.RecordsPerSecond, summary.UpstreamCallsPerSecond)
	}
}

func TestTargetRateLimitBoundsCallsToEachTarget(t *testing.T) {
	c := newCluster(t, nil)
	cfg := c.config()
	cfg.TargetCallsPerSecond = 50
	start := time.Now()
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, make([]spec, 10))))
	if elapsed := time.Since(start); elapsed < 170*time.Millisecond {
		t.Fatalf("elapsed = %v, want at least 170ms", elapsed)
	}
}

func TestCandidateTimeoutIsAnOutcomeAndReplayContinues(t *testing.T) {
	c := newCluster(t, nil)
	var candidateCalls atomic.Int64
	c.c.handler = func(_ http.ResponseWriter, r *http.Request) {
		candidateCalls.Add(1)
		if r.URL.Path == "/hang" {
			<-r.Context().Done()
		}
	}
	cfg := c.config()
	cfg.Timeout = 80 * time.Millisecond
	summary, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{{path: "/hang"}, {path: "/fine"}})))

	if summary.Replayed != 2 {
		t.Fatalf("replayed = %d", summary.Replayed)
	}
	byPath := make(map[string]*RecordResult)
	for _, r := range results {
		byPath[r.Path] = r
	}
	if got := byPath["/hang"].Calls[RoleCandidate].Outcome; got != CallTimeout {
		t.Fatalf("candidate outcome = %s", got)
	}
	if got := byPath["/hang"].Calls[RoleBaselineA].Outcome; got != CallOK {
		t.Fatalf("baseline outcome = %s", got)
	}
	if got := byPath["/fine"].Calls[RoleCandidate].Outcome; got != CallOK {
		t.Fatalf("next record outcome = %s", got)
	}
	// One attempt per record: retries would change load and repeat side effects.
	if n := candidateCalls.Load(); n != 2 {
		t.Fatalf("candidate calls = %d, want 2", n)
	}
	// A candidate failure is what the tool exists to find, not missing evidence.
	if !summary.Complete() {
		t.Fatalf("problems = %v", summary.Problems())
	}
}

type connCalls struct{}

// A server may close a kept-alive connection just as a request is written to it.
// A transport reusing connections treats that as a stale connection and silently
// resends safe methods, so the target can act twice on one record. This server
// forces that: it reads a second request on any connection, counts it, and hangs up.
func TestStaleConnectionsCannotCauseASecondCall(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		onConn := r.Context().Value(connCalls{}).(*atomic.Int64)
		if onConn.Add(1) > 1 {
			if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
				_ = conn.Close()
			}
		}
	}))
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connCalls{}, new(atomic.Int64))
	}
	server.Start()
	defer server.Close()

	c := newCluster(t, nil)
	cfg := c.config()
	cfg.Candidate.URL = server.URL
	cfg.AllowedOrigins = []string{c.a.URL, c.b.URL, server.URL}
	cfg.Concurrency = 3 // One record at a time, so each can reuse the last connection.
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, make([]spec, 4))))
	if got := calls.Load(); got != 4 {
		t.Fatalf("target received %d calls for 4 records, and the summary counted %d", got, summary.Targets["candidate"].Calls)
	}
}

func TestFailedBaselineMeansIncompleteEvidence(t *testing.T) {
	c := newCluster(t, nil)
	c.b.Close()
	summary, results := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, []spec{{path: "/x"}})))
	if got := results[0].Calls[RoleBaselineB].Outcome; got != CallConnectionError {
		t.Fatalf("outcome = %s", got)
	}
	if summary.Complete() {
		t.Fatal("a failed baseline can't produce complete evidence")
	}
	if !strings.Contains(strings.Join(summary.Problems(), ";"), "baseline") {
		t.Fatalf("problems = %v", summary.Problems())
	}
}

func TestErrorsNeverCarryURLsIntoResults(t *testing.T) {
	c := newCluster(t, nil)
	c.c.Close()
	secretish := "token=visible-in-a-url-error"
	summary, results := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, []spec{{path: "/x", query: secretish}})))
	data, err := json.Marshal(struct {
		S *Summary
		O CallResult
	}{summary, results[0].Calls[RoleCandidate]})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(secretish)) {
		t.Fatalf("outcome holds the URL: %s", data)
	}
}

func TestOversizedResponseIsBoundedAndRecorded(t *testing.T) {
	c := newCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 4096))
	})
	cfg := c.config()
	cfg.MaxResponseBytes = 1024
	_, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{{path: "/big"}})))
	call := results[0].Calls[RoleCandidate]
	if call.Outcome != CallResponseTooLarge || len(call.Body) != 0 {
		t.Fatalf("outcome = %s, body bytes held = %d", call.Outcome, len(call.Body))
	}
}

func TestCancellationStopsPromptlyAndLeavesNoGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()
	started := make(chan struct{})
	var once sync.Once
	var canceledUpstream atomic.Int64
	c := newCluster(t, func(_ http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done()
		canceledUpstream.Add(1)
	})
	cfg := c.config()
	cfg.Timeout = time.Minute
	engine, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ds := scan(t, writeDataset(t, make([]spec, 200)))

	type outcome struct {
		summary *Summary
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		summary, err := engine.Run(ctx, ds, nil)
		done <- outcome{summary, err}
	}()
	<-started
	cancel()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.summary.Interrupted || got.summary.Complete() {
			t.Fatalf("summary = %+v", got.summary)
		}
		if got.summary.Replayed+got.summary.NotReplayed != 200 {
			t.Fatalf("replayed %d + not replayed %d must account for every record", got.summary.Replayed, got.summary.NotReplayed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after cancellation")
	}
	// Run returns as soon as the context ends. The servers notice the dropped
	// connections slightly later.
	reached := time.Now().Add(5 * time.Second)
	for canceledUpstream.Load() == 0 {
		if time.Now().After(reached) {
			t.Fatal("cancellation didn't reach the targets")
		}
		time.Sleep(5 * time.Millisecond)
	}
	engine.Close()
	c.a.Close()
	c.b.Close()
	c.c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutines = %d, baseline %d:\n%s", runtime.NumGoroutine(), baseline, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDatasetDamageMakesTheRunIncompleteButItContinues(t *testing.T) {
	dir := writeDataset(t, []spec{{path: "/a"}, {path: "/b"}, {path: "/c"}})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, entries[0].Name())
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-3); err != nil {
		t.Fatal(err)
	}
	c := newCluster(t, nil)
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, dir))
	if len(c.a.seen()) == 0 {
		t.Fatal("readable records must still be replayed")
	}
	if summary.Complete() || summary.Dataset.UnsealedSegments == 0 {
		t.Fatalf("summary = %+v, problems = %v", summary, summary.Problems())
	}
}

func TestRecordChangedAfterScanIsCounted(t *testing.T) {
	dir := writeDataset(t, []spec{{path: "/a"}})
	ds := scan(t, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("gone"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newCluster(t, nil)
	summary, _ := mustRun(t, mustEngine(t, c.config()), ds)
	if summary.LoadFailures != 1 || summary.Complete() {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestCaptureDropsAreCarriedIntoTheSummary(t *testing.T) {
	dir := t.TempDir()
	enc, err := traffic.NewEncoder(traffic.EncoderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	w, err := traffic.NewWriter(dir, traffic.WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := enc.Encode(&traffic.Record{
		SchemaVersion: traffic.SchemaVersion, ID: "a", Seq: 1, CapturedAt: time.Now(), Protocol: traffic.ProtocolHTTP11,
		Request: traffic.Request{Method: "GET", Path: "/", Body: traffic.Body{State: traffic.BodyEmpty}},
		Outcome: traffic.Outcome{Transport: traffic.TransportOK}, Replay: traffic.ReplayInfo{Eligible: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.CloseWithDrops(map[string]int64{"queue_full": 9}); err != nil {
		t.Fatal(err)
	}
	c := newCluster(t, nil)
	summary, _ := mustRun(t, mustEngine(t, c.config()), scan(t, dir))
	if summary.CaptureDrops["queue_full"] != 9 {
		t.Fatalf("summary = %+v", summary)
	}
}
