package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type comparisonReport struct {
	Verdict          string `json:"verdict"`
	EvidenceComplete bool   `json:"evidence_complete"`
	Comparison       *struct {
		Counts   map[string]int `json:"counts"`
		Coverage struct {
			Records  int `json:"records"`
			Compared int `json:"compared"`
		} `json:"coverage"`
		Findings []struct {
			Severity string `json:"severity"`
			Kind     string `json:"kind"`
			Route    string `json:"route"`
			Path     string `json:"path"`
			Count    int    `json:"count"`
			Evidence *struct {
				RecordID  string `json:"record_id"`
				Candidate struct {
					Present bool   `json:"present"`
					Type    string `json:"type"`
				} `json:"candidate"`
			} `json:"evidence"`
		} `json:"findings"`
		Noise []struct {
			Route    string `json:"route"`
			Path     string `json:"path"`
			Decision string `json:"decision"`
		} `json:"noise"`
		Ignored []struct {
			Route string `json:"route"`
			Path  string `json:"path"`
			Count int    `json:"count"`
		} `json:"ignored"`
		Routes []struct {
			Route   string `json:"route"`
			Latency struct {
				Evaluated bool `json:"evaluated"`
			} `json:"latency"`
		} `json:"routes"`
	} `json:"comparison"`
}

// captureFixtureTraffic stores enough repeated traffic for every noisy field to get
// repeated observations, and enough on one route to evaluate latency.
func captureFixtureTraffic(t *testing.T, s *slice) {
	t.Helper()
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0",
		"--upstream", s.captureSvc.baseURL(t), "--out", s.trafficDir, "--redact", s.policy)
	url := proxy.baseURL(t)
	for i := 1; i <= 5; i++ {
		httpGet(t, fmt.Sprintf("%s/v1/orders/ord-%d", url, i), nil)
		httpGet(t, fmt.Sprintf("%s/v1/users/usr-%d", url, i), nil)
		httpGet(t, fmt.Sprintf("%s/v1/inventory/sku%d", url, i), nil)
		httpGet(t, url+"/v1/catalog", nil)
	}
	httpGet(t, url+"/v1/orders/ord-missing", nil)
	for range 25 {
		httpGet(t, url+"/v1/reports/daily", nil)
	}
	if err := proxy.stop(t); err != nil {
		t.Fatalf("capture exit: %v\n%s", err, proxy.output())
	}
}

// deployForDiff uses a candidate slow enough on the latency route to rise clearly above
// timing jitter on a busy machine.
func deployForDiff(t *testing.T) *slice {
	t.Helper()
	work := t.TempDir()
	s := &slice{
		work:       work,
		trafficDir: filepath.Join(work, "traffic"),
		policy:     writeFile(t, filepath.Join(work, "redact.yaml"), e2ePolicy),
	}
	fixture := func(variant, instance string) *process {
		return start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", variant, "--instance", instance, "--candidate-latency", "120ms")
	}
	s.captureSvc = fixture("baseline", "capture")
	s.a, s.b, s.c = fixture("baseline", "a"), fixture("baseline", "b"), fixture("candidate", "c")
	s.aURL, s.bURL, s.cURL = s.a.baseURL(t), s.b.baseURL(t), s.c.baseURL(t)
	return s
}

func runComparison(t *testing.T, s *slice, extra ...string) (*comparisonReport, []byte, result) {
	t.Helper()
	path := filepath.Join(s.work, "report.json")
	run := runCommand(t, nil, "replaydiff", s.runArgs(path, extra...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no report (exit %d): %s", run.code, run.stderr)
	}
	var report comparisonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Comparison == nil {
		t.Fatalf("report has no comparison: %s", data)
	}
	return &report, data, run
}

func findingKeys(report *comparisonReport, severities ...string) []string {
	var out []string
	for _, f := range report.Comparison.Findings {
		if slices.Contains(severities, f.Severity) {
			out = append(out, f.Severity+" "+f.Kind+" "+f.Route+" "+f.Path)
		}
	}
	slices.Sort(out)
	return out
}

// TestSeededRegressionsAreDetectedAndNoiseIsExplained is the acceptance test for
// comparison, using real processes. The expected lists are exact and come from
// docs/fixtures.md, so anything extra is a false positive and anything missing is a
// regression the tool failed to find.
func TestSeededRegressionsAreDetectedAndNoiseIsExplained(t *testing.T) {
	s := deployForDiff(t)
	captureFixtureTraffic(t, s)
	report, raw, run := runComparison(t, s)
	if run.code != 0 {
		t.Fatalf("run exit %d: %s", run.code, run.stderr)
	}
	if report.Verdict != "not_evaluated" || !report.EvidenceComplete {
		t.Fatalf("report = %s", raw)
	}

	wantRegressions := []string{
		"breaking field_removed GET /v1/inventory/* $.warehouse_hint",
		"breaking field_removed GET /v1/orders/* $.customer.tier",
		"breaking status_class_changed GET /v1/orders/ord-missing ",
		"breaking type_changed GET /v1/inventory/* $.stock_estimate",
		"breaking type_changed GET /v1/orders/* $.total",
		"warning latency_regression GET /v1/reports/daily p50",
		"warning latency_regression GET /v1/reports/daily p95",
		"warning latency_regression GET /v1/reports/daily p99",
		"warning value_changed GET /v1/users/* $.display_name",
	}
	if got := findingKeys(report, "breaking", "warning"); !slices.Equal(got, wantRegressions) {
		t.Fatalf("regressions:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(wantRegressions, "\n      "))
	}

	if got := findingKeys(report, "uncertain"); len(got) != 0 {
		t.Fatalf("with repeated observations nothing should be uncertain: %v", got)
	}

	wantInfo := []string{
		"info field_added GET /v1/users/* $.loyalty_points",
		"info noise_explained GET /v1/catalog $.generated_at",
		"info noise_explained GET /v1/catalog $.request_id",
		"info noise_explained GET /v1/inventory/* $.server_time",
		"info noise_explained GET /v1/orders/* $.request_id",
		"info noise_explained GET /v1/orders/* $.server_time",
		"info noise_explained GET /v1/users/* $.request_id",
		"info noise_explained GET /v1/users/* $.server_time",
	}
	if got := findingKeys(report, "info"); !slices.Equal(got, wantInfo) {
		t.Fatalf("info:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(wantInfo, "\n      "))
	}

	// The control route has nothing but explained noise.
	for _, f := range report.Comparison.Findings {
		if f.Route == "GET /v1/catalog" && f.Kind != "noise_explained" {
			t.Fatalf("control route finding: %+v", f)
		}
	}
	// Noise never excused structure on the noisy route.
	for _, decision := range report.Comparison.Noise {
		if decision.Decision != "explained" {
			t.Fatalf("decision = %+v", decision)
		}
		if strings.HasSuffix(decision.Path, "stock_estimate") || strings.HasSuffix(decision.Path, "warehouse_hint") {
			t.Fatalf("a structural change was treated as noise: %+v", decision)
		}
	}

	// Every record was compared, and the seeded record is cited.
	if report.Comparison.Coverage.Records != 46 || report.Comparison.Coverage.Compared != 46 {
		t.Fatalf("coverage = %+v", report.Comparison.Coverage)
	}
	for _, f := range report.Comparison.Findings {
		if f.Kind == "field_removed" && (f.Evidence == nil || f.Evidence.RecordID == "" || f.Evidence.Candidate.Present) {
			t.Fatalf("finding has no usable evidence: %+v", f)
		}
	}
	// Latency was only evaluated where there were enough samples.
	for _, route := range report.Comparison.Routes {
		if want := route.Route == "GET /v1/reports/daily"; route.Latency.Evaluated != want {
			t.Fatalf("route %s evaluated = %t", route.Route, route.Latency.Evaluated)
		}
	}
	// Values the policy covers stay out of the report, though targets returned them.
	if strings.Contains(string(raw), "@customers.example.test") {
		t.Fatal("report holds a value the policy covers")
	}

	gate := runCommand(t, nil, "replaydiff", "report", filepath.Join(s.work, "report.json"))
	if gate.code != 1 {
		t.Fatalf("report exit %d", gate.code)
	}
	for _, want := range []string{"field_removed", "$.customer.tier", "breaking", "latency_regression"} {
		if !strings.Contains(string(gate.stdout), want) {
			t.Fatalf("report output lacks %q:\n%s", want, gate.stdout)
		}
	}
}

func TestDiffConfigPermitsDifferencesAndShowsItDid(t *testing.T) {
	s := deployForDiff(t)
	captureFixtureTraffic(t, s)
	config := writeFile(t, filepath.Join(s.work, "diff.yaml"), `
ignore:
  - route: "GET /v1/users/*"
    paths: ["$.display_name"]
  - route: "GET /v1/orders/*"
    paths: ["$.total"]
`)
	report, _, run := runComparison(t, s, "--diff-config", config)
	if run.code != 0 {
		t.Fatalf("run exit %d: %s", run.code, run.stderr)
	}
	keys := findingKeys(report, "breaking", "warning")
	if slices.Contains(keys, "warning value_changed GET /v1/users/* $.display_name") {
		t.Fatalf("ignored value still reported: %v", keys)
	}
	// The rule covers values, so the retyped total is still breaking.
	if !slices.Contains(keys, "breaking type_changed GET /v1/orders/* $.total") {
		t.Fatalf("ignore rule hid a structural change: %v", keys)
	}
	found := false
	for _, ignored := range report.Comparison.Ignored {
		if ignored.Route == "GET /v1/users/*" && ignored.Path == "$.display_name" && ignored.Count == 5 {
			found = true
		}
	}
	if !found {
		t.Fatalf("ignored = %+v", report.Comparison.Ignored)
	}
}

func TestSingleObservationOfNoiseIsReportedAsUncertain(t *testing.T) {
	s := deployForDiff(t)
	captureOne(t, s)
	report, _, _ := runComparison(t, s)
	got := findingKeys(report, "uncertain")
	want := []string{
		"uncertain insufficient_baseline_evidence GET /v1/catalog $.generated_at",
		"uncertain insufficient_baseline_evidence GET /v1/catalog $.request_id",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("uncertain = %v", got)
	}
}

func TestRunRefusesToCompareWithoutARedactionPolicy(t *testing.T) {
	s := deployForDiff(t)
	captureOne(t, s)
	args := s.runArgs(filepath.Join(s.work, "report.json"))
	var withoutPolicy []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--redact" {
			i++
			continue
		}
		withoutPolicy = append(withoutPolicy, args[i])
	}
	got := runCommand(t, nil, "replaydiff", withoutPolicy...)
	if got.code != 2 || !strings.Contains(string(got.stderr), "--redact") {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
}

// A limit means part of the evidence wasn't compared, so the run can't claim to be complete.
func TestReachedComparisonLimitCannotExitZero(t *testing.T) {
	s := deployForDiff(t)
	captureFixtureTraffic(t, s)
	config := writeFile(t, filepath.Join(s.work, "diff.yaml"), `limits: {max_routes: 1}`)
	_, _, run := runComparison(t, s, "--diff-config", config)
	if run.code != 2 {
		t.Fatalf("run exit %d: %s", run.code, run.stderr)
	}
	if !strings.Contains(string(run.stderr), "route_limit_reached") {
		t.Fatalf("stderr = %s", run.stderr)
	}
}
