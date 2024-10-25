package e2e

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var adminAddr = regexp.MustCompile(`admin_addr=(127\.0\.0\.1:\d+)`)

// adminURL waits for a process to report its admin listener.
func (p *process) adminURL(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := adminAddr.FindStringSubmatch(p.output()); m != nil {
			return "http://" + m[1]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no admin address; logs:\n%s", p.output())
	return ""
}

func fetch(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// The admin listener is separate from the proxy, so scrapes and probes are never
// recorded, and its counters match what capture prints when it stops.
func TestCaptureServesMetricsAndHealthOnItsOwnListener(t *testing.T) {
	work := t.TempDir()
	service := start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", "baseline", "--instance", "a")
	policy := writeFile(t, work+"/redact.yaml", e2ePolicy)
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0", "--admin-listen", "127.0.0.1:0",
		"--upstream", service.baseURL(t), "--out", work+"/traffic", "--redact", policy)
	url, admin := proxy.baseURL(t), proxy.adminURL(t)
	for range 3 {
		httpGet(t, url+"/v1/catalog", nil)
	}
	for _, path := range []string{"/livez", "/readyz"} {
		if code, _ := fetch(t, admin+path); code != http.StatusOK {
			t.Fatalf("%s: %d", path, code)
		}
	}
	var metrics string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, metrics = fetch(t, admin+"/metrics")
		if strings.Contains(metrics, "replaydiff_capture_records_persisted_total 3\n") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, line := range []string{
		"replaydiff_capture_exchanges_total 3\n",
		"replaydiff_capture_records_persisted_total 3\n",
		`replaydiff_capture_exchange_duration_seconds_count{protocol="http/1.1"} 3` + "\n",
	} {
		if !strings.Contains(metrics, line) {
			t.Errorf("metrics lack %q", strings.TrimSpace(line))
		}
	}
	if err := proxy.stop(t); err != nil {
		t.Fatalf("capture exit: %v\n%s", err, proxy.output())
	}
	if n := scanDir(t, work+"/traffic"); n == 0 {
		t.Fatal("no traffic written")
	}
}

// otlpCollector is a stand-in OTLP/HTTP endpoint that keeps every export it receives.
type otlpCollector struct {
	*httptest.Server
	mu       sync.Mutex
	payloads [][]byte
}

func newCollector(t *testing.T) *otlpCollector {
	t.Helper()
	c := &otlpCollector{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/v1/traces" {
			c.mu.Lock()
			c.payloads = append(c.payloads, data)
			c.mu.Unlock()
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *otlpCollector) received() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.payloads, nil)
}

// Spans from capture and run reach the collector, and none holds traffic content, which
// is planted in the path, query, a header and the body.
func TestTracesAreExportedWithoutTrafficContent(t *testing.T) {
	secret := newSentinel(t)
	collector := newCollector(t)
	env := []string{"OTEL_EXPORTER_OTLP_ENDPOINT=" + collector.URL}
	s := deploySlice(t)
	proxy := start(t, env, "replaydiff", "capture", "--listen", "127.0.0.1:0",
		"--upstream", s.captureSvc.baseURL(t), "--out", s.trafficDir, "--redact", s.policy)
	url := proxy.baseURL(t)
	for range 3 {
		httpGet(t, url+"/v1/orders/"+secret+"?token="+secret, map[string]string{"X-Note": secret})
	}
	if err := proxy.stop(t); err != nil {
		t.Fatalf("capture exit: %v\n%s", err, proxy.output())
	}
	captured := collector.received()
	if !bytes.Contains(captured, []byte("replaydiff capture")) {
		t.Fatalf("no capture spans exported (%d bytes)", len(captured))
	}

	run := runCommand(t, env, "replaydiff", s.runArgs(filepath.Join(s.work, "report.json"))...)
	if run.code != 0 {
		t.Fatalf("run exit %d: %s", run.code, run.stderr)
	}
	all := collector.received()
	if !bytes.Contains(all, []byte("replaydiff replay call")) {
		t.Fatalf("no replay spans exported")
	}
	assertAbsent(t, "exported spans", all, secret)
}
