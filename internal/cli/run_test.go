package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bispulm/replaydiff/internal/diff"
	"github.com/Bispulm/replaydiff/internal/replay"
	"github.com/Bispulm/replaydiff/internal/report"
)

func runCLI(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunRejectsInvalidInvocations(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	a, b, c := "http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3"
	policy := writePolicy(t, "")
	base := func(extra ...string) []string {
		return append([]string{"run", "--traffic", dir, "--redact", policy, "--baseline-a", a, "--baseline-b", b, "--candidate", c, "--report", report}, extra...)
	}
	allowAll := []string{"--allow-origin", a, "--allow-origin", b, "--allow-origin", c}

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no traffic":         {[]string{"run", "--redact", policy, "--baseline-a", a, "--baseline-b", b, "--candidate", c, "--report", report}, "--traffic"},
		"no candidate":       {[]string{"run", "--redact", policy, "--traffic", dir, "--baseline-a", a, "--baseline-b", b, "--report", report}, "--candidate"},
		"no report":          {[]string{"run", "--redact", policy, "--traffic", dir, "--baseline-a", a, "--baseline-b", b, "--candidate", c}, "--report"},
		"no policy":          {[]string{"run", "--traffic", dir, "--baseline-a", a, "--baseline-b", b, "--candidate", c, "--report", report, "--allow-origin", a}, "--redact"},
		"missing policy":     {append(base(allowAll...), "--redact", policy+".absent"), "policy"},
		"bad diff config":    {base(append(allowAll, "--diff-config", policy+".absent")...), "diff config"},
		"invalid diff rule":  {base(append(allowAll, "--diff-config", writePolicy(t, "ignores: []"))...), "diff config"},
		"no allowlist":       {base(), "--allow-origin"},
		"candidate unlisted": {base("--allow-origin", a, "--allow-origin", b), "allowlist"},
		"bad credential":     {base(append(allowAll, "--target-credential", "nonsense")...), "ROLE:Header=ENV_VAR"},
		"unknown role":       {base(append(allowAll, "--target-credential", "other:A=B")...), "unknown role"},
		"unset credential":   {base(append(allowAll, "--target-credential", "candidate:A=REPLAYDIFF_TEST_UNSET")...), "REPLAYDIFF_TEST_UNSET"},
		"trace allowed":      {base(append(allowAll, "--allow-method", "TRACE")...), "TRACE"},
		"empty dataset":      {base(allowAll...), "no traffic segments"},
		"missing ca file":    {base(append(allowAll, "--target-ca-file", report+".absent")...), "--target-ca-file"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCLI(tc.args...)
			if code != ExitFailure {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr, tc.want)
			}
		})
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatalf("a failed invocation must not leave a report: %v", err)
	}
}

func writeRun(t *testing.T, run *report.Run) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := report.Write(path, run); err != nil {
		t.Fatal(err)
	}
	return path
}

func completeRun(findings ...diff.Finding) *report.Run {
	counts := map[diff.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return &report.Run{
		Schema:           report.Schema,
		Verdict:          report.VerdictNotEvaluated,
		EvidenceComplete: true,
		Summary: &replay.Summary{
			Records:  3,
			Eligible: 3,
			Replayed: 3,
			Targets: map[string]*replay.TargetSummary{
				"baseline-a": {Calls: 3, Outcomes: map[string]int64{"ok": 3}, Statuses: map[string]int64{"2xx": 3}},
				"baseline-b": {Calls: 3, Outcomes: map[string]int64{"ok": 3}, Statuses: map[string]int64{"2xx": 3}},
				"candidate":  {Calls: 3, Outcomes: map[string]int64{"ok": 3}, Statuses: map[string]int64{"2xx": 3}},
			},
		},
		Comparison: &diff.Result{Counts: counts, Coverage: diff.Coverage{Records: 3, Compared: 3}, Findings: findings},
	}
}

func removedField() diff.Finding {
	return diff.Finding{Severity: diff.SeverityBreaking, Kind: diff.KindFieldRemoved, Route: "GET /a", Path: "$.x", Count: 2}
}

func TestReportExitCodesFollowTheVerdict(t *testing.T) {
	changed := diff.Finding{Severity: diff.SeverityWarning, Kind: diff.KindValueChanged, Route: "GET /a", Path: "$.y", Count: 1}
	if code, stdout, _ := runCLI("report", writeRun(t, completeRun())); code != ExitOK || !strings.Contains(stdout, "verdict: pass") {
		t.Fatalf("clean: exit %d: %s", code, stdout)
	}
	if code, stdout, _ := runCLI("report", writeRun(t, completeRun(removedField()))); code != ExitRegression || !strings.Contains(stdout, "verdict: regression") {
		t.Fatalf("breaking: exit %d: %s", code, stdout)
	}
	if code, _, _ := runCLI("report", writeRun(t, completeRun(changed))); code != ExitOK {
		t.Fatalf("warning: exit %d", code)
	}
	if code, _, _ := runCLI("report", writeRun(t, completeRun(changed)), "--fail-on", "breaking,warning"); code != ExitRegression {
		t.Fatalf("warning with --fail-on: exit %d", code)
	}
	incomplete := completeRun()
	incomplete.Summary.Dataset.CorruptRecords = 1
	if code, stdout, _ := runCLI("report", writeRun(t, incomplete)); code != ExitFailure || !strings.Contains(stdout, "verdict: incomplete") {
		t.Fatalf("incomplete: exit %d: %s", code, stdout)
	}
}

func TestReportAcceptsTheFileBeforeOrAfterFlags(t *testing.T) {
	path := writeRun(t, completeRun())
	for _, args := range [][]string{
		{"report", path, "--quiet"},
		{"report", "--quiet", path},
	} {
		code, stdout, stderr := runCLI(args...)
		if code != ExitOK || stdout != "verdict: pass\n" {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestReportWritesEveryFormat(t *testing.T) {
	dir := t.TempDir()
	jsonPath, junitPath, markdownPath := filepath.Join(dir, "gate.json"), filepath.Join(dir, "junit.xml"), filepath.Join(dir, "summary.md")
	code, _, stderr := runCLI("report", writeRun(t, completeRun(removedField())), "--json", jsonPath, "--junit", junitPath, "--markdown", markdownPath)
	if code != ExitRegression {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for path, want := range map[string]string{jsonPath: report.GateSchema, junitPath: "<testsuites", markdownPath: "# replaydiff: Regression"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("%s lacks %q:\n%s", path, want, data)
		}
	}
}

// A clean verdict mustn't survive losing its output, or a CI job would pass with no record.
func TestUnwritableOutputCannotPass(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "junit.xml")
	if code, _, _ := runCLI("report", writeRun(t, completeRun()), "--junit", missing); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
}

func TestReportRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := writeRun(t, completeRun())
	for name, args := range map[string][]string{
		"no file":                  {"report"},
		"two files":                {"report", valid, valid},
		"missing file":             {"report", filepath.Join(dir, "absent.json")},
		"not json":                 {"report", write("bad.json", "nope")},
		"unknown schema":           {"report", write("other.json", `{"schema":"other/v9"}`)},
		"unknown field":            {"report", write("field.json", `{"schema":"replaydiff.run/v1","extra":1}`)},
		"missing summary":          {"report", write("empty.json", `{"schema":"replaydiff.run/v1"}`)},
		"bad policy file":          {"report", valid, "--policy", write("policy.yaml", "fail_ons: []")},
		"absent policy":            {"report", valid, "--policy", filepath.Join(dir, "absent.yaml")},
		"bad fail-on":              {"report", valid, "--fail-on", "nonsense"},
		"fail-on without breaking": {"report", valid, "--fail-on", "warning"},
		"null target":              {"report", write("nulltarget.json", `{"schema":"replaydiff.run/v1","summary":{"targets":{"candidate":null}}}`)},
		"unknown flag":             {"report", valid, "--nope"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := runCLI(args...); code != ExitFailure {
				t.Fatalf("exit code = %d", code)
			}
		})
	}
}

func TestRunRejectsANonFiniteRate(t *testing.T) {
	dir := t.TempDir()
	policy := writePolicy(t, "")
	a, b, c := "http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3"
	code, _, stderr := runCLI("run", "--traffic", dir, "--redact", policy, "--report", filepath.Join(dir, "r.json"),
		"--baseline-a", a, "--baseline-b", b, "--candidate", c, "--allow-origin", a, "--allow-origin", b, "--allow-origin", c, "--rps", "NaN")
	if code != ExitFailure || !strings.Contains(stderr, "rate") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestSamplesAreBoundedDeterministicAndHoldNoResponseData(t *testing.T) {
	set := newSampleSet(3)
	for _, seq := range []uint64{5, 2, 9, 1, 7, 3} {
		result := &replay.RecordResult{Seq: seq, ID: "x"}
		result.Calls[0].Body = []byte("response data")
		set.add(result)
	}
	var got []uint64
	for _, item := range set.sorted() {
		got = append(got, item.Seq)
		if item.Calls[0].Body != nil {
			t.Fatal("sample kept response data")
		}
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("samples = %v, want the three lowest", got)
	}
}
