package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

const testPolicy = `
query_params: [token]
json_paths: ["$.user.email", "$.items[*].card", "$..password"]
session:
  sources: ["cookie:sid"]
`

func sentinel(t *testing.T) string {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "rdsentinel" + hex.EncodeToString(b[:])
}

// syncBuffer collects log output from concurrent goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	t        *testing.T
	dir      string
	logs     *syncBuffer
	upstream *httptest.Server
	proxy    *httptest.Server
	capture  *Capture
	closed   bool
}

func newHarness(t *testing.T, upstream http.Handler, adjust ...func(*Config)) *harness {
	t.Helper()
	policy, err := redact.ParsePolicy([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redact.NewEngine(policy, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	h := &harness{t: t, dir: filepath.Join(t.TempDir(), "traffic"), logs: &syncBuffer{}}
	h.upstream = httptest.NewServer(upstream)
	t.Cleanup(h.upstream.Close)
	target, err := url.Parse(h.upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Upstream: target,
		Dir:      h.dir,
		Engine:   engine,
		Logger:   slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, f := range adjust {
		f(&cfg)
	}
	h.capture, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.proxy = httptest.NewServer(h.capture)
	t.Cleanup(h.close)
	return h
}

// close shuts down in the order a real process does.
func (h *harness) close() {
	h.t.Helper()
	if h.closed {
		return
	}
	h.closed = true
	h.proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.capture.Close(ctx); err != nil {
		h.t.Errorf("Close: %v", err)
	}
}

func (h *harness) records() []*traffic.Record {
	h.t.Helper()
	h.close()
	ds, err := traffic.Scan(h.dir, traffic.ScanOptions{})
	if err != nil {
		h.t.Fatalf("Scan: %v", err)
	}
	defer func() { _ = ds.Close() }()
	if !ds.Integrity.Complete() {
		h.t.Fatalf("integrity problems: %v", ds.Integrity.Problems())
	}
	out := make([]*traffic.Record, 0, len(ds.Entries))
	for _, e := range ds.Entries {
		rec, err := ds.Load(e)
		if err != nil {
			h.t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func (h *harness) onlyRecord() *traffic.Record {
	h.t.Helper()
	records := h.records()
	if len(records) != 1 {
		h.t.Fatalf("records = %d, want 1", len(records))
	}
	return records[0]
}

type reply struct {
	status  int
	header  http.Header
	trailer http.Header
	body    []byte
	readErr error
}

// send issues a request through the proxy and reads the whole response. A read
// error is returned in the reply, since some tests expect one.
func (h *harness) send(method, target string, body []byte, header map[string]string) reply {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, h.proxy.URL+target, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if body == nil {
		req.Body = http.NoBody
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(resp.Body)
	return reply{status: resp.StatusCode, header: resp.Header, trailer: resp.Trailer, body: data, readErr: readErr}
}

// assertNoSecret scans everything capture produced: raw segment bytes, decoded
// records, decoded bodies, base64 and percent-encoded forms, and the logs.
func (h *harness) assertNoSecret(secrets ...string) {
	h.t.Helper()
	h.close()
	haystacks := map[string][]byte{"logs": []byte(h.logs.String())}

	entries, err := os.ReadDir(h.dir)
	if err != nil && !os.IsNotExist(err) {
		h.t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(h.dir, entry.Name()))
		if err != nil {
			h.t.Fatal(err)
		}
		haystacks["file "+entry.Name()] = data
	}
	if len(entries) > 0 {
		ds, err := traffic.Scan(h.dir, traffic.ScanOptions{})
		if err != nil {
			h.t.Fatal(err)
		}
		defer func() { _ = ds.Close() }()
		for _, e := range ds.Entries {
			rec, err := ds.Load(e)
			if err != nil {
				h.t.Fatal(err)
			}
			encoded, err := json.Marshal(rec)
			if err != nil {
				h.t.Fatal(err)
			}
			haystacks["record "+rec.ID] = encoded
			if rec.Response != nil {
				haystacks["response body "+rec.ID] = rec.Response.Body.Data
			}
			haystacks["request body "+rec.ID] = rec.Request.Body.Data
		}
	}
	for where, data := range haystacks {
		for _, secret := range secrets {
			if containsSecret(data, secret) {
				h.t.Errorf("sentinel found in %s:\n%s", where, truncate(data))
			}
		}
	}
}

func truncate(data []byte) string {
	if len(data) > 800 {
		return string(data[:800]) + "..."
	}
	return string(data)
}

func containsSecret(data []byte, secret string) bool {
	if bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte(url.QueryEscape(secret))) {
		return true
	}
	for pad := range 3 {
		encoded := base64.StdEncoding.EncodeToString(append(make([]byte, pad), secret...))
		core := encoded[(pad*8+5)/6 : len(encoded)-4]
		if bytes.Contains(data, []byte(core)) {
			return true
		}
	}
	return false
}

// waitForGoroutines fails if the count doesn't return to the baseline.
func waitForGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= baseline {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines = %d, baseline %d:\n%s", n, baseline, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitFor polls a condition, for state that changes off the request path.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

func hasString(values []string, want string) bool {
	for _, v := range values {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}
