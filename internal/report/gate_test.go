package report

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Bispulm/replaydiff/internal/diff"
	"github.com/Bispulm/replaydiff/internal/replay"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// completeRun is a run with complete evidence and no findings.
func completeRun() *Run {
	return &Run{
		Schema:           Schema,
		Verdict:          VerdictNotEvaluated,
		EvidenceComplete: true,
		Summary: &replay.Summary{
			Dataset:  traffic.Integrity{Segments: 1, Records: 10},
			Records:  10,
			Eligible: 10,
			Replayed: 10,
			Targets: map[string]*replay.TargetSummary{
				"baseline-a": {Calls: 10, Outcomes: map[string]int64{"ok": 10}},
				"baseline-b": {Calls: 10, Outcomes: map[string]int64{"ok": 10}},
				"candidate":  {Calls: 10, Outcomes: map[string]int64{"ok": 10}},
			},
		},
		Comparison: &diff.Result{
			Counts:   map[diff.Severity]int{},
			Coverage: diff.Coverage{Records: 10, Compared: 10},
		},
	}
}

func finding(severity diff.Severity, kind diff.Kind, route, path string) diff.Finding {
	return diff.Finding{Severity: severity, Kind: kind, Route: route, Path: path, Count: 1}
}

func withFindings(findings ...diff.Finding) *Run {
	run := completeRun()
	run.Comparison.Findings = findings
	for _, f := range findings {
		run.Comparison.Counts[f.Severity]++
	}
	return run
}

func mustPolicy(t *testing.T, doc string) *Policy {
	t.Helper()
	policy, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func breaking() diff.Finding {
	return finding(diff.SeverityBreaking, diff.KindFieldRemoved, "GET /a", "$.x")
}

func warning() diff.Finding {
	return finding(diff.SeverityWarning, diff.KindValueChanged, "GET /a", "$.y")
}

func latency() diff.Finding {
	return finding(diff.SeverityWarning, diff.KindLatencyRegression, "GET /a", "p99")
}

func uncertain() diff.Finding {
	return finding(diff.SeverityUncertain, diff.KindInsufficientEvidence, "GET /a", "$.z")
}

func TestVerdicts(t *testing.T) {
	info := finding(diff.SeverityInfo, diff.KindFieldAdded, "GET /a", "$.n")
	noise := finding(diff.SeverityInfo, diff.KindNoiseExplained, "GET /a", "$.t")
	for name, tc := range map[string]struct {
		run    *Run
		policy string
		want   Verdict
		code   int
	}{
		"clean":                         {completeRun(), "", VerdictPass, 0},
		"info and noise pass":           {withFindings(info, noise), "", VerdictPass, 0},
		"breaking fails by default":     {withFindings(breaking()), "", VerdictRegression, 1},
		"warning passes by default":     {withFindings(warning()), "", VerdictPass, 0},
		"warning can fail":              {withFindings(warning()), "fail_on: [breaking, warning]", VerdictRegression, 1},
		"one kind can fail":             {withFindings(latency()), "fail_on: [breaking, latency_regression]", VerdictRegression, 1},
		"other kinds stay passing":      {withFindings(warning()), "fail_on: [breaking, latency_regression]", VerdictPass, 0},
		"breaking can be turned off":    {withFindings(warning()), "fail_on: [latency_regression]", VerdictPass, 0},
		"uncertain isn't a pass":        {withFindings(uncertain()), "", VerdictIncomplete, 2},
		"uncertain can be allowed":      {withFindings(uncertain()), "evidence: {max_uncertain: 1}", VerdictPass, 0},
		"allowance has a limit":         {withFindings(uncertain(), uncertain()), "evidence: {max_uncertain: 1}", VerdictIncomplete, 2},
		"uncertain kind can be excused": {withFindings(uncertain()), "evidence: {allow_uncertain: [insufficient_baseline_evidence]}", VerdictPass, 0},
		"other kind isn't excused": {withFindings(finding(diff.SeverityUncertain, diff.KindBodyNotCompared, "GET /a", "")),
			"evidence: {allow_uncertain: [insufficient_baseline_evidence]}", VerdictIncomplete, 2},
		"regression outranks incomplete": {withFindings(breaking(), uncertain()), "", VerdictRegression, 1},
	} {
		t.Run(name, func(t *testing.T) {
			decision := Evaluate(tc.run, mustPolicy(t, tc.policy))
			if decision.Verdict != tc.want || decision.ExitCode != tc.code {
				t.Fatalf("verdict = %s exit = %d, want %s %d\nproblems: %v", decision.Verdict, decision.ExitCode, tc.want, tc.code, decision.Problems)
			}
		})
	}
}

// Whatever a run claims about itself, its evidence is judged from the raw figures.
func TestEvidenceProblemsCannotPass(t *testing.T) {
	for name, damage := range map[string]func(*Run){
		"zero eligible records": func(r *Run) { r.Summary.Eligible, r.Summary.Replayed = 0, 0 },
		"dataset damage":        func(r *Run) { r.Summary.Dataset.CorruptRecords = 1 },
		"unsealed segment":      func(r *Run) { r.Summary.Dataset.UnsealedSegments = 1 },
		"interrupted":           func(r *Run) { r.Summary.Interrupted = true },
		"record not replayed":   func(r *Run) { r.Summary.NotReplayed = 1 },
		"load failure":          func(r *Run) { r.Summary.LoadFailures = 1 },
		"baseline failure": func(r *Run) {
			r.Summary.Targets["baseline-b"].Outcomes = map[string]int64{"ok": 9, "timeout": 1}
		},
		"comparison missing":        func(r *Run) { r.Comparison = nil },
		"nothing compared":          func(r *Run) { r.Comparison.Coverage.Compared = 0 },
		"comparison missed records": func(r *Run) { r.Comparison.Coverage.Records = 9 },
		"summary missing":           func(r *Run) { r.Summary = nil },
		"stored problem":            func(r *Run) { r.Problems = []string{"recorded at run time"} },
		"stored incomplete":         func(r *Run) { r.EvidenceComplete = false },
	} {
		t.Run(name, func(t *testing.T) {
			run := completeRun()
			damage(run)
			decision := Evaluate(run, mustPolicy(t, ""))
			if decision.Verdict != VerdictIncomplete || decision.ExitCode != 2 {
				t.Fatalf("verdict = %s exit = %d", decision.Verdict, decision.ExitCode)
			}
			if len(decision.Problems) == 0 {
				t.Fatal("no problem reported")
			}
		})
	}
}

func TestEvidenceCompleteClaimIsNotTrusted(t *testing.T) {
	run := completeRun()
	run.EvidenceComplete = true
	run.Problems = nil
	run.Summary.Dataset.CorruptRecords = 3
	if decision := Evaluate(run, mustPolicy(t, "")); decision.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s", decision.Verdict)
	}
}

func TestCaptureDropsFollowPolicy(t *testing.T) {
	run := func(drops int64) *Run {
		r := completeRun()
		r.Summary.Records = 99
		r.Summary.CaptureDrops = map[string]int64{"queue_full": drops}
		return r
	}
	if d := Evaluate(run(1), mustPolicy(t, "")); d.Verdict != VerdictIncomplete {
		t.Fatalf("by default any drop is incomplete, got %s", d.Verdict)
	}
	if d := Evaluate(run(1), mustPolicy(t, "evidence: {max_capture_drop_percent: 1}")); d.Verdict != VerdictPass {
		t.Fatalf("1 of 100 is within 1%%, got %s: %v", d.Verdict, d.Problems)
	}
	if d := Evaluate(run(2), mustPolicy(t, "evidence: {max_capture_drop_percent: 1}")); d.Verdict != VerdictIncomplete {
		t.Fatalf("2 of 101 is over 1%%, got %s", d.Verdict)
	}
}

func TestSkippedRecordsFollowPolicy(t *testing.T) {
	run := func() *Run {
		r := completeRun()
		r.Summary.Records = 10
		r.Summary.Eligible = 5
		r.Summary.Replayed = 5
		r.Summary.Skipped = map[string]int{"mutating_method": 5}
		r.Comparison.Coverage = diff.Coverage{Records: 5, Compared: 5}
		return r
	}
	if d := Evaluate(run(), mustPolicy(t, "")); d.Verdict != VerdictPass {
		t.Fatalf("skipping is allowed by default, got %s: %v", d.Verdict, d.Problems)
	}
	if d := Evaluate(run(), mustPolicy(t, "evidence: {max_skipped_percent: 50}")); d.Verdict != VerdictPass {
		t.Fatalf("exactly at the limit passes, got %s: %v", d.Verdict, d.Problems)
	}
	if d := Evaluate(run(), mustPolicy(t, "evidence: {max_skipped_percent: 49}")); d.Verdict != VerdictIncomplete {
		t.Fatalf("over the limit is incomplete, got %s", d.Verdict)
	}
}

func TestMinComparedFollowsPolicy(t *testing.T) {
	if d := Evaluate(completeRun(), mustPolicy(t, "evidence: {min_compared: 10}")); d.Verdict != VerdictPass {
		t.Fatalf("verdict = %s", d.Verdict)
	}
	if d := Evaluate(completeRun(), mustPolicy(t, "evidence: {min_compared: 11}")); d.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s", d.Verdict)
	}
}

func TestWaiversExcuseOnlyWhatTheyName(t *testing.T) {
	const waiver = `
waivers:
  - route: "GET /a"
    kinds: [field_removed]
    paths: ["$.x"]
    reason: "Removed on purpose, see issue 12"
`
	for name, tc := range map[string]struct {
		finding diff.Finding
		want    Verdict
	}{
		"named":       {breaking(), VerdictPass},
		"inside path": {finding(diff.SeverityBreaking, diff.KindFieldRemoved, "GET /a", "$.x.y"), VerdictPass},
		"other route": {finding(diff.SeverityBreaking, diff.KindFieldRemoved, "GET /b", "$.x"), VerdictRegression},
		"other kind":  {finding(diff.SeverityBreaking, diff.KindTypeChanged, "GET /a", "$.x"), VerdictRegression},
		"other path":  {finding(diff.SeverityBreaking, diff.KindFieldRemoved, "GET /a", "$.xy"), VerdictRegression},
		"no path":     {finding(diff.SeverityBreaking, diff.KindFieldRemoved, "GET /a", ""), VerdictRegression},
	} {
		t.Run(name, func(t *testing.T) {
			decision := Evaluate(withFindings(tc.finding), mustPolicy(t, waiver))
			if decision.Verdict != tc.want {
				t.Fatalf("verdict = %s", decision.Verdict)
			}
		})
	}
}

func TestWaivedFindingsStayVisibleWithTheirReason(t *testing.T) {
	const waiver = `waivers: [{route: "GET /a", kinds: [field_removed], reason: "On purpose"}]`
	decision := Evaluate(withFindings(breaking()), mustPolicy(t, waiver))
	if len(decision.Findings) != 1 || decision.Findings[0].Disposition != DispositionWaived || decision.Findings[0].Reason != "On purpose" {
		t.Fatalf("findings = %+v", decision.Findings)
	}
}

func TestWaiverWithoutPathsCoversTheRouteAndKind(t *testing.T) {
	const waiver = `waivers: [{route: "GET /a", kinds: [field_removed], reason: "On purpose"}]`
	for _, path := range []string{"", "$.x", "$.y.z"} {
		decision := Evaluate(withFindings(finding(diff.SeverityBreaking, diff.KindFieldRemoved, "GET /a", path)), mustPolicy(t, waiver))
		if decision.Verdict != VerdictPass {
			t.Fatalf("path %q: verdict = %s", path, decision.Verdict)
		}
	}
}

func TestUnusedWaiversAreReported(t *testing.T) {
	const doc = `
waivers:
  - {route: "GET /a", kinds: [field_removed], reason: "Used"}
  - {route: "GET /gone", kinds: [field_removed], reason: "Stale"}
`
	decision := Evaluate(withFindings(breaking()), mustPolicy(t, doc))
	if len(decision.UnusedWaivers) != 1 || decision.UnusedWaivers[0].Route != "GET /gone" {
		t.Fatalf("unused = %+v", decision.UnusedWaivers)
	}
}

// A waiver is about a known change. It can't paper over missing evidence.
func TestWaiversCannotExcuseEvidenceProblems(t *testing.T) {
	run := withFindings(breaking())
	run.Summary.Dataset.CorruptRecords = 1
	decision := Evaluate(run, mustPolicy(t, `waivers: [{route: "GET /a", kinds: [field_removed], reason: "On purpose"}]`))
	if decision.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s", decision.Verdict)
	}
}

func TestLimitNoticesCountAsUncertain(t *testing.T) {
	run := completeRun()
	notice := finding(diff.SeverityUncertain, diff.KindFieldLimitReached, "GET /a", "")
	run.Comparison.Limited = []diff.Finding{notice}
	run.Comparison.Counts[diff.SeverityUncertain] = 1
	if d := Evaluate(run, mustPolicy(t, "")); d.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s", d.Verdict)
	}
	// A notice is judged like any other finding, so a policy can accept it knowingly.
	if d := Evaluate(run, mustPolicy(t, "evidence: {allow_uncertain: [field_limit_reached]}")); d.Verdict != VerdictPass {
		t.Fatalf("verdict = %s: %v", d.Verdict, d.Problems)
	}
}

// Findings left out of the list still count, and can't slip through unexamined.
func TestTruncatedFindingsCannotPass(t *testing.T) {
	t.Run("unlisted breaking fails", func(t *testing.T) {
		run := withFindings(warning())
		run.Comparison.Counts[diff.SeverityBreaking] = 3
		run.Comparison.Truncated.Findings = 3
		decision := Evaluate(run, mustPolicy(t, ""))
		if decision.Verdict != VerdictRegression || decision.UnlistedFailures != 3 {
			t.Fatalf("decision = %+v", decision)
		}
	})
	t.Run("unlisted warnings can't be judged by kind", func(t *testing.T) {
		run := withFindings(warning())
		run.Comparison.Counts[diff.SeverityWarning] = 5
		run.Comparison.Truncated.Findings = 4
		if decision := Evaluate(run, mustPolicy(t, "fail_on: [latency_regression]")); decision.Verdict != VerdictIncomplete {
			t.Fatalf("verdict = %s", decision.Verdict)
		}
	})
	t.Run("waivers can't reach unlisted findings", func(t *testing.T) {
		run := withFindings(breaking())
		run.Comparison.Counts[diff.SeverityBreaking] = 2
		run.Comparison.Truncated.Findings = 1
		decision := Evaluate(run, mustPolicy(t, `waivers: [{route: "GET /a", kinds: [field_removed], reason: "On purpose"}]`))
		if decision.Verdict != VerdictRegression {
			t.Fatalf("verdict = %s", decision.Verdict)
		}
	})
}

func TestDispositionsAreSpecific(t *testing.T) {
	run := withFindings(breaking(), warning(), uncertain(), finding(diff.SeverityInfo, diff.KindFieldAdded, "GET /a", "$.n"))
	decision := Evaluate(run, mustPolicy(t, ""))
	got := make(map[diff.Kind]Disposition)
	for _, f := range decision.Findings {
		got[f.Kind] = f.Disposition
	}
	want := map[diff.Kind]Disposition{
		diff.KindFieldRemoved:         DispositionFailed,
		diff.KindValueChanged:         DispositionAllowed,
		diff.KindInsufficientEvidence: DispositionInconclusive,
		diff.KindFieldAdded:           DispositionAllowed,
	}
	for kind, disposition := range want {
		if got[kind] != disposition {
			t.Errorf("%s = %s, want %s", kind, got[kind], disposition)
		}
	}
}

func TestParsePolicyRejectsInvalidInput(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown key":           `fail_ons: [breaking]`,
		"unknown nested":        `evidence: {max_uncertainty: 1}`,
		"unknown severity":      `fail_on: [catastrophic]`,
		"empty fail_on entry":   `fail_on: [""]`,
		"unknown allow kind":    `evidence: {allow_uncertain: [nope]}`,
		"allowing certain kind": `evidence: {allow_uncertain: [field_removed]}`,
		"negative uncertain":    `evidence: {max_uncertain: -1}`,
		"negative drop":         `evidence: {max_capture_drop_percent: -1}`,
		"drop over 100":         `evidence: {max_capture_drop_percent: 101}`,
		"skip over 100":         `evidence: {max_skipped_percent: 101}`,
		"negative compared":     `evidence: {min_compared: -1}`,
		"waiver without reason": `waivers: [{route: "GET /a", kinds: [field_removed]}]`,
		"blank reason":          `waivers: [{route: "GET /a", kinds: [field_removed], reason: "  "}]`,
		"waiver without route":  `waivers: [{kinds: [field_removed], reason: "x"}]`,
		"waiver without kinds":  `waivers: [{route: "GET /a", reason: "x"}]`,
		"waiver unknown kind":   `waivers: [{route: "GET /a", kinds: [nope], reason: "x"}]`,
		"two documents":         "fail_on: [breaking]\n---\nfail_on: [warning]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(doc)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestPolicyDefaultsAndLoading(t *testing.T) {
	policy, err := LoadPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policy.FailOn, []string{"breaking"}) || policy.Evidence.MinCompared != 1 || policy.Evidence.MaxSkippedPercent != 100 {
		t.Fatalf("policy = %+v", policy)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`fail_on: [warning]`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err = LoadPolicy(path)
	if err != nil || !slices.Equal(policy.FailOn, []string{"warning"}) {
		t.Fatalf("policy = %+v, err = %v", policy, err)
	}
	if _, err := LoadPolicy(path + ".absent"); err == nil {
		t.Fatal("want error")
	}
}

func TestSetFailOnOverridesThePolicy(t *testing.T) {
	policy := mustPolicy(t, "")
	if err := policy.SetFailOn("breaking,latency_regression"); err != nil {
		t.Fatal(err)
	}
	if d := Evaluate(withFindings(latency()), policy); d.Verdict != VerdictRegression {
		t.Fatalf("verdict = %s", d.Verdict)
	}
	if err := policy.SetFailOn("nonsense"); err == nil {
		t.Fatal("want error")
	}
	if err := policy.SetFailOn(""); err == nil {
		t.Fatal("an empty list would never fail anything")
	}
}

func TestRunFileRoundTripsAndRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	run := withFindings(breaking())
	if err := Write(path, run); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if d := Evaluate(loaded, mustPolicy(t, "")); d.Verdict != VerdictRegression {
		t.Fatalf("verdict = %s", d.Verdict)
	}
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, file := range map[string]string{
		"missing":        filepath.Join(dir, "absent.json"),
		"not json":       write("bad.json", "nope"),
		"unknown schema": write("other.json", `{"schema":"other/v9"}`),
		"unknown field":  write("field.json", `{"schema":"`+Schema+`","extra":1}`),
		"trailing data":  write("trail.json", `{"schema":"`+Schema+`"} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(file); err == nil {
				t.Fatal("want error")
			}
		})
	}
	for _, entry := range mustReadDir(t, dir) {
		if strings.HasPrefix(entry, ".replaydiff-report-") {
			t.Fatalf("temporary file left behind: %s", entry)
		}
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
