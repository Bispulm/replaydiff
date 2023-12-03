package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// slice is a deployment for one capture-to-replay test: a service to capture
// from, plus fresh replicas to replay against. The capture service is separate
// because capturing changes its state, and replay targets must start equal.
type slice struct {
	work       string
	trafficDir string
	policy     string
	captureSvc *process
	a, b, c    *process
	aURL       string
	bURL       string
	cURL       string
}

func deploySlice(t *testing.T) *slice {
	t.Helper()
	work := t.TempDir()
	s := &slice{
		work:       work,
		trafficDir: filepath.Join(work, "traffic"),
		policy:     writeFile(t, filepath.Join(work, "redact.yaml"), e2ePolicy),
	}
	fixture := func(variant, instance string) *process {
		return start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", variant, "--instance", instance)
	}
	s.captureSvc = fixture("baseline", "capture")
	s.a, s.b, s.c = fixture("baseline", "a"), fixture("baseline", "b"), fixture("candidate", "c")
	s.aURL, s.bURL, s.cURL = s.a.baseURL(t), s.b.baseURL(t), s.c.baseURL(t)
	return s
}

func (s *slice) runArgs(report string, extra ...string) []string {
	args := []string{
		"run", "--traffic", s.trafficDir, "--report", report,
		"--baseline-a", s.aURL, "--baseline-b", s.bURL, "--candidate", s.cURL,
		"--allow-origin", s.aURL, "--allow-origin", s.bURL, "--allow-origin", s.cURL,
		"--rps", "0", "--max-samples", "1000",
	}
	return append(args, extra...)
}

type reportFile struct {
	Schema           string   `json:"schema"`
	Verdict          string   `json:"verdict"`
	EvidenceComplete bool     `json:"evidence_complete"`
	Problems         []string `json:"problems"`
	Summary          struct {
		Records       int            `json:"records"`
		Eligible      int            `json:"eligible"`
		Replayed      int            `json:"replayed"`
		Skipped       map[string]int `json:"skipped"`
		UpstreamCalls int64          `json:"upstream_calls"`
		Interrupted   bool           `json:"interrupted"`
	} `json:"summary"`
	Samples []struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Calls  [3]struct {
			Role    string `json:"role"`
			Outcome string `json:"outcome"`
			Status  int    `json:"status"`
		} `json:"calls"`
	} `json:"samples"`
}

func readReport(t *testing.T, path string) (*reportFile, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report reportFile
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return &report, data
}

func fixtureStats(t *testing.T, baseURL string) (requests, mutations int64) {
	t.Helper()
	status, body := httpGet(t, baseURL+"/__fixture/stats", nil)
	if status != http.StatusOK {
		t.Fatalf("stats status = %d", status)
	}
	var stats struct {
		Requests  int64 `json:"requests"`
		Mutations int64 `json:"mutations"`
	}
	if err := json.Unmarshal([]byte(body), &stats); err != nil {
		t.Fatal(err)
	}
	return stats.Requests, stats.Mutations
}

func post(t *testing.T, url, contentType, body string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestCaptureToReplayVerticalSlice is the path a user follows: traffic goes
// through the proxy, sanitized records are stored, and they are replayed against
// two baselines and a candidate. Everything runs as separate processes.
func TestCaptureToReplayVerticalSlice(t *testing.T) {
	s := deploySlice(t)
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0",
		"--upstream", s.captureSvc.baseURL(t), "--out", s.trafficDir, "--redact", s.policy, "--log-level", "debug")
	proxyURL := proxy.baseURL(t)

	authSecret, cookieSecret, querySecret, bodySecret := newSentinel(t), newSentinel(t), newSentinel(t), newSentinel(t)
	targetCredential := newSentinel(t)
	secrets := []string{authSecret, cookieSecret, querySecret, bodySecret, targetCredential}

	withSession := map[string]string{"Authorization": "Bearer " + authSecret, "Cookie": "sid=" + cookieSecret}
	for _, path := range []string{
		"/v1/orders/ord-1?token=" + querySecret,
		"/v1/orders/ord-missing",
		"/v1/users/usr-1",
		"/v1/inventory/sku1",
		"/v1/catalog",
		"/v1/redirect",
		"/v1/me",
		"/v1/cart/s1/step/1",
		"/v1/cart/s1/step/2",
		"/v1/cart/s1/step/3",
	} {
		httpGet(t, proxyURL+path, withSession)
	}
	if status := post(t, proxyURL+"/v1/orders", "application/json", `{"sku":"a"}`); status != http.StatusCreated {
		t.Fatalf("POST status = %d", status)
	}
	if status := post(t, proxyURL+"/v1/login", "application/json", fmt.Sprintf(`{"username":"u","password":%q}`, bodySecret)); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}
	if err := proxy.stop(t); err != nil {
		t.Fatalf("capture exit: %v\n%s", err, proxy.output())
	}

	report := filepath.Join(s.work, "report.json")
	args := s.runArgs(report,
		"--target-credential", "baseline-a:Authorization=RD_E2E_CREDENTIAL",
		"--target-credential", "baseline-b:Authorization=RD_E2E_CREDENTIAL",
		"--target-credential", "candidate:Authorization=RD_E2E_CREDENTIAL",
	)
	run := runCommand(t, []string{"RD_E2E_CREDENTIAL=Bearer " + targetCredential}, "replaydiff", args...)
	if run.code != 0 {
		t.Fatalf("run exit %d\nstdout: %s\nstderr: %s", run.code, run.stdout, run.stderr)
	}

	parsed, raw := readReport(t, report)
	if parsed.Verdict != "not_evaluated" || !parsed.EvidenceComplete {
		t.Fatalf("report = %s", raw)
	}
	const totalRecords, mutating, eligible = 12, 2, 10
	if parsed.Summary.Records != totalRecords || parsed.Summary.Skipped["mutating_method"] != mutating ||
		parsed.Summary.Eligible != eligible || parsed.Summary.Replayed != eligible || parsed.Summary.UpstreamCalls != eligible*3 {
		t.Fatalf("summary = %+v", parsed.Summary)
	}

	// Mutating requests reached no replay target, and each target saw only the
	// eligible records.
	for name, url := range map[string]string{"a": s.aURL, "b": s.bURL, "c": s.cURL} {
		requests, mutations := fixtureStats(t, url)
		if mutations != 0 {
			t.Errorf("target %s: %d mutating calls", name, mutations)
		}
		if requests != eligible+1 { // +1 for this stats call.
			t.Errorf("target %s: %d requests, want %d", name, requests, eligible+1)
		}
	}

	byPath := make(map[string]int)
	for i, sample := range parsed.Samples {
		byPath[sample.Path] = i
	}
	status := func(path string, role int) int {
		i, ok := byPath[path]
		if !ok {
			t.Fatalf("no sample for %s", path)
		}
		return parsed.Samples[i].Calls[role].Status
	}
	const a, b, c = 0, 1, 2
	// Session order held: the cart returns 409 for any step out of order.
	for step := 1; step <= 3; step++ {
		path := fmt.Sprintf("/v1/cart/s1/step/%d", step)
		for _, role := range []int{a, b, c} {
			if got := status(path, role); got != http.StatusOK {
				t.Errorf("%s role %d: status %d", path, role, got)
			}
		}
	}
	// The seeded status regression reaches the results, ready for the diff engine.
	if status("/v1/orders/ord-missing", a) != http.StatusNotFound || status("/v1/orders/ord-missing", c) != http.StatusInternalServerError {
		t.Errorf("seeded regression not visible: a=%d c=%d", status("/v1/orders/ord-missing", a), status("/v1/orders/ord-missing", c))
	}
	// The redirect was recorded and not followed off-origin.
	if status("/v1/redirect", c) != http.StatusFound {
		t.Errorf("redirect status = %d", status("/v1/redirect", c))
	}
	// The stored credential was redacted, and the supplied one took its place.
	if status("/v1/me", a) != http.StatusOK {
		t.Errorf("/v1/me status = %d, want the supplied credential to work", status("/v1/me", a))
	}

	// The invariant, across everything this run produced.
	scanDir(t, s.trafficDir, secrets...)
	assertAbsent(t, "capture logs", []byte(proxy.output()), secrets...)
	assertAbsent(t, "report", raw, secrets...)
	assertAbsent(t, "run stdout", run.stdout, secrets...)
	assertAbsent(t, "run stderr", run.stderr, secrets...)
	inspected := runCommand(t, nil, "replaydiff", "inspect", "--traffic", s.trafficDir)
	assertAbsent(t, "inspect output", inspected.stdout, secrets...)

	// A completed replay still can't pass the gate, since nothing was compared.
	gate := runCommand(t, nil, "replaydiff", "report", report)
	if gate.code != 2 {
		t.Fatalf("report exit %d: %s", gate.code, gate.stdout)
	}
}

// captureOne stores a single GET through a real proxy.
func captureOne(t *testing.T, s *slice) {
	t.Helper()
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0",
		"--upstream", s.captureSvc.baseURL(t), "--out", s.trafficDir, "--redact", s.policy)
	httpGet(t, proxy.baseURL(t)+"/v1/catalog", nil)
	if err := proxy.stop(t); err != nil {
		t.Fatal(err)
	}
}

func TestUnlistedTargetRefusesToStartAndSendsNothing(t *testing.T) {
	s := deploySlice(t)
	captureOne(t, s)
	report := filepath.Join(s.work, "report.json")
	got := runCommand(t, nil, "replaydiff", "run", "--traffic", s.trafficDir, "--report", report,
		"--baseline-a", s.aURL, "--baseline-b", s.bURL, "--candidate", s.cURL,
		"--allow-origin", s.aURL, "--allow-origin", s.bURL)
	if got.code != 2 || !strings.Contains(string(got.stderr), "allowlist") {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	for _, url := range []string{s.aURL, s.bURL, s.cURL} {
		if requests, _ := fixtureStats(t, url); requests != 1 { // Only this stats call.
			t.Errorf("%s received %d requests", url, requests)
		}
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatalf("report written: %v", err)
	}
}

func TestDatasetWithOnlyMutatingRequestsFailsTheRun(t *testing.T) {
	s := deploySlice(t)
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0",
		"--upstream", s.captureSvc.baseURL(t), "--out", s.trafficDir, "--redact", s.policy)
	post(t, proxy.baseURL(t)+"/v1/orders", "application/json", `{"sku":"a"}`)
	if err := proxy.stop(t); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(s.work, "report.json")
	got := runCommand(t, nil, "replaydiff", s.runArgs(report)...)
	if got.code != 2 || !strings.Contains(string(got.stderr), "no eligible") {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	parsed, _ := readReport(t, report)
	if parsed.EvidenceComplete {
		t.Fatal("report claims complete evidence")
	}
}

func TestCorruptDatasetCannotPass(t *testing.T) {
	s := deploySlice(t)
	captureOne(t, s)
	entries, err := os.ReadDir(s.trafficDir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.trafficDir, entries[0].Name())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(s.work, "report.json")
	got := runCommand(t, nil, "replaydiff", s.runArgs(report)...)
	if got.code != 2 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
}

func TestUnknownFormatVersionFailsClearlyBeforeSendingTraffic(t *testing.T) {
	s := deploySlice(t)
	captureOne(t, s)
	entries, err := os.ReadDir(s.trafficDir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.trafficDir, entries[0].Name())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[8], data[9] = 0x00, 0x63 // Format version 99.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got := runCommand(t, nil, "replaydiff", s.runArgs(filepath.Join(s.work, "report.json"))...)
	if got.code != 2 || !strings.Contains(string(got.stderr), "version 99") {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if requests, _ := fixtureStats(t, s.cURL); requests != 1 {
		t.Fatalf("candidate received %d requests", requests)
	}
}

func TestFailedBaselineCannotPass(t *testing.T) {
	s := deploySlice(t)
	captureOne(t, s)
	if err := s.b.stop(t); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(s.work, "report.json")
	got := runCommand(t, nil, "replaydiff", s.runArgs(report)...)
	if got.code != 2 || !strings.Contains(string(got.stderr), "baseline-b") {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
}

func TestInterruptedRunWritesAReportAndCannotPass(t *testing.T) {
	s := deploySlice(t)
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0",
		"--upstream", s.captureSvc.baseURL(t), "--out", s.trafficDir, "--redact", s.policy)
	for range 30 {
		httpGet(t, proxy.baseURL(t)+"/v1/catalog", nil)
	}
	if err := proxy.stop(t); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(s.work, "report.json")
	args := append(s.runArgs(report), "--rps", "10")
	run := start(t, nil, "replaydiff", args...)
	time.Sleep(300 * time.Millisecond)
	if err := run.stop(t); err == nil {
		t.Fatal("an interrupted run must not exit 0")
	}
	if got := run.cmd.ProcessState.ExitCode(); got != 2 {
		t.Fatalf("exit %d: %s", got, run.output())
	}
	parsed, _ := readReport(t, report)
	if !parsed.Summary.Interrupted || parsed.EvidenceComplete {
		t.Fatalf("summary = %+v", parsed.Summary)
	}
}
