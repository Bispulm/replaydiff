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

func TestReportAlwaysFailsClosedForNow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	complete := &runReport{
		Schema:           reportSchema,
		Verdict:          verdictNotEvaluated,
		EvidenceComplete: true,
		Summary:          &replay.Summary{Records: 1, Eligible: 1, Replayed: 1, Targets: map[string]*replay.TargetSummary{"candidate": {Calls: 1, Statuses: map[string]int64{"2xx": 1}}}},
	}
	if err := writeReport(path, complete); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI("report", path)
	if code != ExitFailure {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "verdict: not_evaluated") || !strings.Contains(stdout, "candidate: 1 call(s) 2xx=1") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "no verdict") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestReportPrintsFindingsInOrderWithCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	report := &runReport{
		Schema:  reportSchema,
		Verdict: verdictNotEvaluated,
		Summary: &replay.Summary{Targets: map[string]*replay.TargetSummary{}},
		Comparison: &diff.Result{
			Counts:   map[diff.Severity]int{diff.SeverityBreaking: 1, diff.SeverityWarning: 1},
			Coverage: diff.Coverage{Records: 3, Compared: 2},
			Findings: []diff.Finding{
				{Severity: diff.SeverityBreaking, Kind: diff.KindFieldRemoved, Route: "GET /a", Path: "$.x", Count: 2},
				{Severity: diff.SeverityWarning, Kind: diff.KindLatencyRegression, Route: "GET /b", Path: "p99", Count: 20, Detail: "candidate 9.0ms, slower baseline 1.0ms"},
			},
			Ignored:   []diff.IgnoredField{{Route: "GET /a", Path: "$.t", Count: 4}},
			Truncated: diff.Truncated{Findings: 7},
		},
	}
	if err := writeReport(path, report); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runCLI("report", path)
	if code != ExitFailure {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{
		"compared: 2 of 3 records",
		"findings: 1 breaking, 1 warning, 0 uncertain, 0 info",
		"GET /a $.x (2)",
		"candidate 9.0ms",
		"ignored by rule: GET /a $.t (4)",
		"7 more finding(s) left out",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Index(stdout, "field_removed") > strings.Index(stdout, "latency_regression") {
		t.Errorf("findings out of order:\n%s", stdout)
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
	for name, args := range map[string][]string{
		"no file":         {"report"},
		"two files":       {"report", "a", "b"},
		"missing file":    {"report", filepath.Join(dir, "absent.json")},
		"not json":        {"report", write("bad.json", "nope")},
		"unknown schema":  {"report", write("other.json", `{"schema":"other/v9"}`)},
		"unknown field":   {"report", write("field.json", `{"schema":"replaydiff.run/v1","extra":1}`)},
		"missing summary": {"report", write("empty.json", `{"schema":"replaydiff.run/v1"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := runCLI(args...); code != ExitFailure {
				t.Fatalf("exit code = %d", code)
			}
		})
	}
}

func TestReportFileIsReadableOnlyByItsOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReport(path, &runReport{Schema: reportSchema}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o", perm)
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
