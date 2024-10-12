package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bispulm/replaydiff/internal/diff"
)

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string       `xml:"name,attr"`
	ClassName string       `xml:"classname,attr"`
	Failure   *junitDetail `xml:"failure"`
	Error     *junitDetail `xml:"error"`
	Skipped   *junitDetail `xml:"skipped"`
}

type junitDetail struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

func parseJUnit(t *testing.T, data []byte) junitSuites {
	t.Helper()
	var suites junitSuites
	if err := xml.Unmarshal(data, &suites); err != nil {
		t.Fatalf("not well-formed XML: %v\n%s", err, data)
	}
	return suites
}

func renderJUnit(t *testing.T, run *Run, policy string) (junitSuites, []byte) {
	t.Helper()
	data, err := JUnit(run, Evaluate(run, mustPolicy(t, policy)))
	if err != nil {
		t.Fatal(err)
	}
	return parseJUnit(t, data), data
}

func allCases(suites junitSuites) []junitCase {
	var out []junitCase
	for _, suite := range suites.Suites {
		out = append(out, suite.Cases...)
	}
	return out
}

func TestJUnitMapsDispositions(t *testing.T) {
	run := withFindings(breaking(), warning(), uncertain(), finding(diff.SeverityBreaking, diff.KindTypeChanged, "GET /b", "$.k"))
	suites, _ := renderJUnit(t, run, `waivers: [{route: "GET /b", kinds: [type_changed], reason: "On purpose"}]`)

	byName := make(map[string]junitCase)
	for _, c := range allCases(suites) {
		byName[c.Name] = c
	}
	if c := byName["field_removed $.x"]; c.Failure == nil || c.Failure.Type != "field_removed" || c.ClassName != "GET /a" {
		t.Errorf("breaking finding = %+v", c)
	}
	if c := byName["value_changed $.y"]; c.Failure != nil || c.Error != nil || c.Skipped != nil {
		t.Errorf("an allowed warning must pass: %+v", c)
	}
	if c := byName["insufficient_baseline_evidence $.z"]; c.Error == nil {
		t.Errorf("uncertain must be an error, not a failure of the code: %+v", c)
	}
	if c := byName["type_changed $.k"]; c.Skipped == nil || !strings.Contains(c.Skipped.Message, "On purpose") {
		t.Errorf("waived = %+v", c)
	}
	if suites.Failures != 1 || suites.Skipped != 1 || suites.Errors < 1 {
		t.Errorf("totals = %d failures, %d errors, %d skipped", suites.Failures, suites.Errors, suites.Skipped)
	}
}

func TestJUnitTotalsMatchTheCases(t *testing.T) {
	suites, _ := renderJUnit(t, withFindings(breaking(), warning(), uncertain()), "")
	tests, failures, errors, skipped := 0, 0, 0, 0
	for _, suite := range suites.Suites {
		suiteFailures, suiteErrors, suiteSkipped := 0, 0, 0
		for _, c := range suite.Cases {
			switch {
			case c.Failure != nil:
				suiteFailures++
			case c.Error != nil:
				suiteErrors++
			case c.Skipped != nil:
				suiteSkipped++
			}
		}
		if suite.Tests != len(suite.Cases) || suite.Failures != suiteFailures || suite.Errors != suiteErrors || suite.Skipped != suiteSkipped {
			t.Errorf("suite %q attributes disagree with its cases: %+v", suite.Name, suite)
		}
		tests += len(suite.Cases)
		failures += suiteFailures
		errors += suiteErrors
		skipped += suiteSkipped
	}
	if suites.Tests != tests || suites.Failures != failures || suites.Errors != errors || suites.Skipped != skipped {
		t.Errorf("totals = %+v, want %d %d %d %d", suites, tests, failures, errors, skipped)
	}
}

// A clean run must show as tests that ran and passed. Zero tests looks like nothing happened.
func TestJUnitForACleanRunHasPassingTests(t *testing.T) {
	run := completeRun()
	run.Comparison.Routes = []diff.RouteSummary{{Route: "GET /a", Records: 3}}
	suites, _ := renderJUnit(t, run, "")
	if suites.Tests == 0 || suites.Failures != 0 || suites.Errors != 0 {
		t.Fatalf("totals = %+v", suites)
	}
	names := make([]string, 0)
	for _, c := range allCases(suites) {
		names = append(names, c.Name)
	}
	joined := strings.Join(names, ";")
	if !strings.Contains(joined, "evidence is complete") {
		t.Errorf("cases = %v", names)
	}
	routeSeen := false
	for _, suite := range suites.Suites {
		if suite.Name == "GET /a" {
			routeSeen = len(suite.Cases) == 1 && suite.Cases[0].Name == "no findings"
		}
	}
	if !routeSeen {
		t.Errorf("a route with no findings must still show as a passing test: %+v", suites.Suites)
	}
}

func TestJUnitReportsEachEvidenceProblemAsAnError(t *testing.T) {
	run := completeRun()
	run.Summary.Dataset.CorruptRecords = 1
	run.Summary.Interrupted = true
	suites, _ := renderJUnit(t, run, "")
	errors := 0
	for _, c := range allCases(suites) {
		if c.Error != nil {
			errors++
		}
	}
	if errors < 2 || suites.Errors != errors {
		t.Fatalf("errors = %d, totals = %+v", errors, suites)
	}
}

// Routes and paths come from traffic, so a hostile request mustn't be able to break the file.
func TestJUnitEscapesHostileContent(t *testing.T) {
	hostileRoute := `GET /a"><testcase name="injected"/><![CDATA[x]]>`
	hostilePath := `$['<b>&"']` + "\x00\x1b"
	f := finding(diff.SeverityBreaking, diff.KindFieldRemoved, hostileRoute, hostilePath)
	f.Evidence = &diff.Evidence{RecordID: "r", Seq: 1, BaselineA: diff.Value{Present: true, Type: "string", Text: `</failure><evil/>`}}
	suites, data := renderJUnit(t, withFindings(f), "")
	if bytes.Contains(data, []byte(`<evil`)) || bytes.Contains(data, []byte(`<testcase name="injected"`)) {
		t.Fatalf("content wasn't escaped:\n%s", data)
	}
	for _, c := range allCases(suites) {
		if c.Name == "injected" {
			t.Fatal("a hostile route injected a test case")
		}
	}
	if !bytes.HasPrefix(data, []byte(xml.Header)) {
		t.Fatalf("no XML header: %.40s", data)
	}
}

func TestJUnitIsDeterministic(t *testing.T) {
	run := withFindings(breaking(), warning(), finding(diff.SeverityBreaking, diff.KindTypeChanged, "GET /z", "$.a"), finding(diff.SeverityBreaking, diff.KindTypeChanged, "GET /m", "$.a"))
	_, first := renderJUnit(t, run, "")
	_, second := renderJUnit(t, run, "")
	if !bytes.Equal(first, second) {
		t.Fatal("output differs between renders")
	}
}

func renderMarkdown(t *testing.T, run *Run, policy string) string {
	t.Helper()
	return Markdown(run, Evaluate(run, mustPolicy(t, policy)))
}

func TestMarkdownStatesTheVerdictFirstAndExplainsIt(t *testing.T) {
	for _, tc := range []struct {
		run  *Run
		want []string
	}{
		{withFindings(breaking()), []string{"Regression", "field_removed", "GET /a", "$.x"}},
		{completeRun(), []string{"Pass"}},
		{withFindings(uncertain()), []string{"Incomplete", "insufficient_baseline_evidence"}},
	} {
		out := renderMarkdown(t, tc.run, "")
		first, _, _ := strings.Cut(out, "\n")
		if !strings.Contains(first, tc.want[0]) {
			t.Errorf("first line = %q, want it to state %q", first, tc.want[0])
		}
		for _, want := range tc.want {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
	}
}

func TestMarkdownSeparatesFailuresFromAllowedFindings(t *testing.T) {
	out := renderMarkdown(t, withFindings(breaking(), warning()), "")
	failedSection, allowedSection, found := strings.Cut(out, "## Allowed by the policy")
	if !found {
		t.Fatalf("no allowed section:\n%s", out)
	}
	if !strings.Contains(failedSection, "field_removed") || strings.Contains(failedSection, "value_changed") {
		t.Fatalf("an allowed finding is shown as failing:\n%s", failedSection)
	}
	if !strings.Contains(allowedSection, "value_changed") {
		t.Fatalf("allowed section:\n%s", allowedSection)
	}
}

func TestMarkdownShowsCoverageAndWaivers(t *testing.T) {
	run := withFindings(breaking())
	run.Summary.Skipped = map[string]int{"mutating_method": 4}
	run.Summary.CaptureDrops = map[string]int64{"queue_full": 2}
	run.Comparison.Noise = []diff.NoiseDecision{{Route: "GET /a", Path: "$.t", Type: "string", Decision: diff.NoiseExplained, Observations: 5, BaselineDisagreements: 5, CandidateDifferences: 5, BaselineRate: 1, CandidateRate: 1}}
	out := renderMarkdown(t, run, `{evidence: {max_capture_drop_percent: 100}, waivers: [{route: "GET /a", kinds: [field_removed], reason: "Removed on purpose"}, {route: "GET /gone", kinds: [type_changed], reason: "Stale one"}]}`)
	for _, want := range []string{"mutating_method", "queue_full", "Removed on purpose", "Stale one", "$.t"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// Markdown from a route or path could otherwise break the table or inject HTML into a
// pull request summary.
func TestMarkdownEscapesHostileContent(t *testing.T) {
	route := "GET /a|b\n# heading <script>alert(1)</script>"
	path := "$['`x`|<img src=y>']"
	f := finding(diff.SeverityBreaking, diff.KindFieldRemoved, route, path)
	f.Evidence = &diff.Evidence{RecordID: "r", Seq: 1, BaselineA: diff.Value{Present: true, Type: "string", Text: "<script>|`\nvalue"}}
	out := renderMarkdown(t, withFindings(f), "")
	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") {
		t.Fatalf("HTML wasn't escaped:\n%s", out)
	}
	if strings.Contains(out, "\n# heading") {
		t.Fatalf("a newline in a route started a new block:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "|") && strings.Contains(line, "field_removed") {
			unescaped := strings.Count(line, "|") - strings.Count(line, `\|`)
			if unescaped != 8 {
				t.Fatalf("table row has %d separators, want 8: %s", unescaped, line)
			}
		}
	}
}

func TestMarkdownIsBounded(t *testing.T) {
	findings := make([]diff.Finding, 0, 500)
	for i := range 500 {
		findings = append(findings, finding(diff.SeverityBreaking, diff.KindFieldRemoved, "GET /a", fmt.Sprintf("$.f%03d", i)))
	}
	out := renderMarkdown(t, withFindings(findings...), "")
	if strings.Contains(out, "$.f499") {
		t.Fatal("output isn't bounded")
	}
	if !strings.Contains(out, "more") {
		t.Fatalf("output doesn't say rows were left out:\n%.400s", out)
	}
	if len(out) > 256<<10 {
		t.Fatalf("size = %d", len(out))
	}
}

func TestTextShowsVerdictReasonsAndFindings(t *testing.T) {
	run := withFindings(breaking(), uncertain())
	run.Comparison.Ignored = []diff.IgnoredField{{Route: "GET /a", Path: "$.t", Count: 4}}
	var out bytes.Buffer
	Text(&out, run, Evaluate(run, mustPolicy(t, "")))
	text := out.String()
	for _, want := range []string{"verdict: regression", "field_removed", "GET /a $.x", "failed", "ignored by rule: GET /a $.t (4)"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
}

func TestDecisionEncodesForTheJSONOutput(t *testing.T) {
	run := withFindings(breaking())
	data, err := JSON(run, Evaluate(run, mustPolicy(t, "")))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Schema   string `json:"schema"`
		Decision struct {
			Verdict  string `json:"verdict"`
			ExitCode int    `json:"exit_code"`
			Findings []struct {
				Disposition string `json:"disposition"`
			} `json:"findings"`
		} `json:"decision"`
		Run struct {
			Schema string `json:"schema"`
		} `json:"run"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Schema != GateSchema || out.Decision.Verdict != "regression" || out.Decision.ExitCode != 1 || out.Run.Schema != Schema || out.Decision.Findings[0].Disposition != "failed" {
		t.Fatalf("out = %+v", out)
	}
}

// The report file is input the gate can't trust. Whatever it holds, the gate must reach a
// verdict rather than panic, and an all-empty document must not be a pass.
func FuzzEvaluateAndRender(f *testing.F) {
	valid, err := json.Marshal(withFindings(breaking(), uncertain()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"schema":"replaydiff.run/v1"}`))
	f.Add([]byte(`{"schema":"replaydiff.run/v1","summary":{"targets":{"candidate":null}}}`))
	f.Add([]byte(`{"schema":"replaydiff.run/v1","summary":{"targets":{}},"comparison":{"findings":[{"severity":"info","kind":"nope"}],"counts":{"breaking":-1}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "run.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		run, err := Load(path)
		if err != nil {
			return
		}
		policy, err := ParsePolicy(nil)
		if err != nil {
			t.Fatal(err)
		}
		decision := Evaluate(run, policy)
		if decision.Verdict == VerdictPass && (run.Summary == nil || run.Comparison == nil) {
			t.Fatalf("passed without evidence: %s", data)
		}
		if _, err := JUnit(run, decision); err != nil {
			t.Fatal(err)
		}
		_ = Markdown(run, decision)
		Text(io.Discard, run, decision)
		if _, err := JSON(run, decision); err != nil {
			t.Fatal(err)
		}
	})
}
