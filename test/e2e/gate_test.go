package e2e

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deployClean uses the baseline build as the candidate, so there are no regressions.
func deployClean(t *testing.T) *slice {
	t.Helper()
	work := t.TempDir()
	s := &slice{
		work:       work,
		trafficDir: filepath.Join(work, "traffic"),
		policy:     writeFile(t, filepath.Join(work, "redact.yaml"), e2ePolicy),
	}
	fixture := func(instance string) *process {
		return start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", "baseline", "--instance", instance)
	}
	s.captureSvc = fixture("capture")
	s.a, s.b, s.c = fixture("a"), fixture("b"), fixture("c")
	s.aURL, s.bURL, s.cURL = s.a.baseURL(t), s.b.baseURL(t), s.c.baseURL(t)
	return s
}

func gateOutputs(s *slice, extra ...string) ([]string, string, string, string) {
	jsonPath := filepath.Join(s.work, "gate.json")
	junitPath := filepath.Join(s.work, "junit.xml")
	markdownPath := filepath.Join(s.work, "summary.md")
	args := []string{"report", filepath.Join(s.work, "report.json"), "--json", jsonPath, "--junit", junitPath, "--markdown", markdownPath}
	return append(args, extra...), jsonPath, junitPath, markdownPath
}

func TestRegressionFailsTheGateWithReadableOutputInEveryFormat(t *testing.T) {
	s := deployForDiff(t)
	captureFixtureTraffic(t, s)
	if _, _, run := runComparison(t, s); run.code != 0 {
		t.Fatalf("run exit %d: %s", run.code, run.stderr)
	}
	args, jsonPath, junitPath, markdownPath := gateOutputs(s)
	gate := runCommand(t, nil, "replaydiff", args...)
	if gate.code != 1 {
		t.Fatalf("gate exit %d:\n%s\n%s", gate.code, gate.stdout, gate.stderr)
	}
	if !strings.Contains(string(gate.stdout), "verdict: regression") {
		t.Fatalf("stdout = %s", gate.stdout)
	}

	data, err := os.ReadFile(junitPath)
	if err != nil {
		t.Fatal(err)
	}
	var suites struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Errors   int `xml:"errors,attr"`
		Suites   []struct {
			Name  string `xml:"name,attr"`
			Cases []struct {
				Name    string `xml:"name,attr"`
				Failure *struct {
					Text string `xml:",chardata"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(data, &suites); err != nil {
		t.Fatalf("JUnit isn't well-formed: %v", err)
	}
	if suites.Failures != 5 || suites.Errors != 0 || suites.Tests == 0 {
		t.Fatalf("JUnit totals = %+v, want the 5 breaking findings as failures", suites)
	}
	found := false
	for _, suite := range suites.Suites {
		for _, c := range suite.Cases {
			if suite.Name == "GET /v1/orders/*" && c.Name == "field_removed $.customer.tier" && c.Failure != nil && strings.Contains(c.Failure.Text, "(missing)") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("JUnit doesn't describe the removed field: %s", data)
	}

	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(markdown)
	if !strings.HasPrefix(text, "# replaydiff: Regression") {
		t.Fatalf("markdown starts with: %.80s", text)
	}
	for _, want := range []string{"$.customer.tier", "$.stock_estimate", "status_class_changed", "latency_regression", "$.server_time", "Nearest-rank"} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}

	gateJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Decision struct {
			Verdict  string `json:"verdict"`
			ExitCode int    `json:"exit_code"`
			Failed   int    `json:"failed"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(gateJSON, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Decision.Verdict != "regression" || parsed.Decision.ExitCode != 1 || parsed.Decision.Failed != 5 {
		t.Fatalf("decision = %+v", parsed.Decision)
	}

	// Targets returned this value, and the policy covers it.
	for name, content := range map[string][]byte{"junit": data, "markdown": markdown, "json": gateJSON, "stdout": gate.stdout} {
		if strings.Contains(string(content), "@customers.example.test") {
			t.Errorf("%s holds a value the policy covers", name)
		}
	}
}

// A gate that only ever fails is useless. A candidate running the same code must pass, despite
// its timestamps and IDs differing, and that is the real test for false positives.
func TestCleanCandidatePassesTheGate(t *testing.T) {
	s := deployClean(t)
	captureFixtureTraffic(t, s)
	report, raw, run := runComparison(t, s)
	if run.code != 0 {
		t.Fatalf("run exit %d: %s", run.code, run.stderr)
	}
	if got := findingKeys(report, "breaking", "warning", "uncertain"); len(got) != 0 {
		t.Fatalf("false positives on identical code:\n%s", strings.Join(got, "\n"))
	}
	if len(findingKeys(report, "info")) == 0 {
		t.Fatalf("noise should have been explained: %s", raw)
	}
	args, _, junitPath, markdownPath := gateOutputs(s)
	gate := runCommand(t, nil, "replaydiff", args...)
	if gate.code != 0 {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(markdown), "# replaydiff: Pass") {
		t.Fatalf("markdown starts with: %.80s", markdown)
	}
	junit, err := os.ReadFile(junitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(junit), `failures="0"`) || !strings.Contains(string(junit), `errors="0"`) {
		t.Fatalf("junit = %s", junit)
	}
}

func TestFailedBaselineCannotPassTheGate(t *testing.T) {
	s := deployClean(t)
	captureOne(t, s)
	if err := s.b.stop(t); err != nil {
		t.Fatal(err)
	}
	runComparison(t, s)
	gate := runCommand(t, nil, "replaydiff", "report", filepath.Join(s.work, "report.json"))
	if gate.code != 2 || !strings.Contains(string(gate.stdout), "baseline-b") {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
}

func TestZeroEligibleRecordsCannotPassTheGate(t *testing.T) {
	s := deployClean(t)
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0",
		"--upstream", s.captureSvc.baseURL(t), "--out", s.trafficDir, "--redact", s.policy)
	post(t, proxy.baseURL(t)+"/v1/orders", "application/json", `{"sku":"a"}`)
	if err := proxy.stop(t); err != nil {
		t.Fatal(err)
	}
	runComparison(t, s)
	gate := runCommand(t, nil, "replaydiff", "report", filepath.Join(s.work, "report.json"))
	if gate.code != 2 || !strings.Contains(string(gate.stdout), "no eligible") {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
}

func TestCorruptDatasetCannotPassTheGate(t *testing.T) {
	s := deployClean(t)
	captureFixtureTraffic(t, s)
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
	runComparison(t, s)
	gate := runCommand(t, nil, "replaydiff", "report", filepath.Join(s.work, "report.json"))
	if gate.code != 2 {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
}

// A run that failed before writing anything leaves no report, and that can't pass either.
func TestMissingReportCannotPassTheGate(t *testing.T) {
	gate := runCommand(t, nil, "replaydiff", "report", filepath.Join(t.TempDir(), "report.json"))
	if gate.code != 2 {
		t.Fatalf("gate exit %d: %s", gate.code, gate.stdout)
	}
}

// Editing the claim in a report doesn't change the evidence behind it.
func TestEditedEvidenceClaimCannotPassTheGate(t *testing.T) {
	s := deployClean(t)
	captureFixtureTraffic(t, s)
	if err := s.b.stop(t); err != nil {
		t.Fatal(err)
	}
	runComparison(t, s)
	path := filepath.Join(s.work, "report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var run map[string]any
	if err := json.Unmarshal(data, &run); err != nil {
		t.Fatal(err)
	}
	run["evidence_complete"] = true
	delete(run, "problems")
	edited, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	gate := runCommand(t, nil, "replaydiff", "report", path)
	if gate.code != 2 {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
}

func TestTooLittleEvidenceIsIncompleteUntilThePolicyAllowsIt(t *testing.T) {
	s := deployClean(t)
	captureOne(t, s)
	runComparison(t, s)
	path := filepath.Join(s.work, "report.json")
	gate := runCommand(t, nil, "replaydiff", "report", path)
	if gate.code != 2 || !strings.Contains(string(gate.stdout), "insufficient_baseline_evidence") {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
	policy := writeFile(t, filepath.Join(s.work, "policy.yaml"), `evidence: {allow_uncertain: [insufficient_baseline_evidence]}`)
	if gate := runCommand(t, nil, "replaydiff", "report", path, "--policy", policy); gate.code != 0 {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
}

func TestWaiversPassKnownChangesAndStayVisible(t *testing.T) {
	s := deployForDiff(t)
	captureFixtureTraffic(t, s)
	runComparison(t, s)
	path := filepath.Join(s.work, "report.json")
	policy := writeFile(t, filepath.Join(s.work, "policy.yaml"), `
waivers:
  - {route: "GET /v1/orders/*", kinds: [field_removed, type_changed], reason: "New order schema"}
  - {route: "GET /v1/orders/ord-missing", kinds: [status_class_changed], reason: "Accepted for this release"}
  - {route: "GET /v1/inventory/*", kinds: [field_removed, type_changed], reason: "New inventory schema"}
  - {route: "GET /v1/retired", kinds: [field_removed], reason: "Stale waiver"}
`)
	args, _, _, markdownPath := gateOutputs(s, "--policy", policy)
	args[1] = path
	gate := runCommand(t, nil, "replaydiff", args...)
	if gate.code != 0 {
		t.Fatalf("gate exit %d:\n%s", gate.code, gate.stdout)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"New order schema", "Accepted for this release", "Stale waiver", "Unused waivers"} {
		if !strings.Contains(string(markdown), want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
}

func TestWarningsFailTheGateOnlyWhenThePolicySaysSo(t *testing.T) {
	s := deployForDiff(t)
	captureFixtureTraffic(t, s)
	runComparison(t, s)
	path := filepath.Join(s.work, "report.json")
	policy := writeFile(t, filepath.Join(s.work, "policy.yaml"), `
waivers:
  - {route: "GET /v1/orders/*", kinds: [field_removed, type_changed], reason: "Known"}
  - {route: "GET /v1/orders/ord-missing", kinds: [status_class_changed], reason: "Known"}
  - {route: "GET /v1/inventory/*", kinds: [field_removed, type_changed], reason: "Known"}
`)
	if gate := runCommand(t, nil, "replaydiff", "report", path, "--policy", policy); gate.code != 0 {
		t.Fatalf("warnings alone must pass by default: exit %d:\n%s", gate.code, gate.stdout)
	}
	if gate := runCommand(t, nil, "replaydiff", "report", path, "--policy", policy, "--fail-on", "breaking,latency_regression"); gate.code != 1 {
		t.Fatalf("exit %d:\n%s", gate.code, gate.stdout)
	}
}
