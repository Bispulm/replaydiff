package report

import (
	"fmt"
	"slices"

	"github.com/Bispulm/replaydiff/internal/diff"
	"github.com/Bispulm/replaydiff/internal/replay"
)

// Verdict is the gate's conclusion.
type Verdict string

// Verdicts.
const (
	// VerdictPass means the evidence is complete and the policy is met.
	VerdictPass Verdict = "pass"
	// VerdictRegression means a finding violates the policy.
	VerdictRegression Verdict = "regression"
	// VerdictIncomplete means the evidence can't support a conclusion.
	VerdictIncomplete Verdict = "incomplete"
)

// Exit codes. These are a stable contract for CI scripts.
const (
	ExitPass       = 0
	ExitRegression = 1
	ExitIncomplete = 2
)

// Disposition says what the policy made of one finding.
type Disposition string

// Dispositions.
const (
	// DispositionFailed means the finding is a regression under this policy.
	DispositionFailed Disposition = "failed"
	// DispositionInconclusive means the finding counts against the evidence.
	DispositionInconclusive Disposition = "inconclusive"
	// DispositionWaived means a waiver excused it.
	DispositionWaived Disposition = "waived"
	// DispositionAllowed means the policy permits it.
	DispositionAllowed Disposition = "allowed"
)

// JudgedFinding is a finding with what the policy made of it.
type JudgedFinding struct {
	diff.Finding
	Disposition Disposition `json:"disposition"`
	// Reason is the waiver's reason, for a waived finding.
	Reason string `json:"reason,omitempty"`
}

// Decision is the gate's full reasoning.
type Decision struct {
	Verdict  Verdict `json:"verdict"`
	ExitCode int     `json:"exit_code"`
	// Problems lists why the evidence is incomplete, whatever the verdict.
	Problems []string `json:"problems,omitempty"`
	// Findings lists every listed finding with its disposition.
	Findings []JudgedFinding `json:"findings,omitempty"`
	Failed   int             `json:"failed"`
	// UnlistedFailures counts failures among findings left out of the list by a limit.
	UnlistedFailures int `json:"unlisted_failures,omitempty"`
	Inconclusive     int `json:"inconclusive"`
	Waived           int `json:"waived"`
	// UnusedWaivers matched nothing in this run, so they may be stale.
	UnusedWaivers []Waiver `json:"unused_waivers,omitempty"`
	Policy        *Policy  `json:"policy"`
}

// Evaluate applies a policy to a run. Evidence is judged from the raw figures instead of the
// run's own claim, and figures that disagree with each other can't pass, which catches a
// damaged, stale or inconsistent file. A report isn't signed, so this isn't protection from
// someone deliberately forging one. See docs/ci.md.
func Evaluate(run *Run, policy *Policy) *Decision {
	decision := &Decision{Policy: policy}
	decision.Problems = evidenceProblems(run, policy)

	if run.Comparison != nil {
		judgeFindings(run.Comparison, policy, decision)
	}

	switch {
	case decision.Failed > 0 || decision.UnlistedFailures > 0:
		// A confirmed regression is the most useful thing to report, even if some evidence
		// is also missing. The reasons for both are in the decision.
		decision.Verdict = VerdictRegression
		decision.ExitCode = ExitRegression
	case len(decision.Problems) > 0:
		decision.Verdict = VerdictIncomplete
		decision.ExitCode = ExitIncomplete
	default:
		decision.Verdict = VerdictPass
		decision.ExitCode = ExitPass
	}
	return decision
}

func evidenceProblems(run *Run, policy *Policy) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if run.Summary == nil {
		add("the report has no run summary")
		return problems
	}
	problems = append(problems, summaryInconsistencies(run.Summary)...)
	// Both sources count. The recomputed one doesn't depend on what the file claims, and the
	// stored one holds anything only the run itself could see.
	problems = append(problems, run.Summary.Problems()...)
	for _, problem := range run.Problems {
		if !slices.Contains(problems, problem) {
			problems = append(problems, problem)
		}
	}
	if !run.EvidenceComplete && len(problems) == 0 {
		add("the run reported incomplete evidence")
	}

	evidence := policy.Evidence
	summary := run.Summary
	var dropped int64
	for _, n := range summary.CaptureDrops {
		dropped += n
	}
	if seen := int64(summary.Records) + dropped; seen > 0 && dropped > 0 {
		if percent := float64(dropped) / float64(seen) * 100; percent > evidence.MaxCaptureDropPercent {
			add("capture dropped %d of %d exchanges (%.2f%%), over the %.2f%% allowed", dropped, seen, percent, evidence.MaxCaptureDropPercent)
		}
	}
	var skipped int
	for _, n := range summary.Skipped {
		skipped += n
	}
	if summary.Records > 0 {
		if percent := float64(skipped) / float64(summary.Records) * 100; percent > evidence.MaxSkippedPercent {
			add("%d of %d records were skipped (%.2f%%), over the %.2f%% allowed", skipped, summary.Records, percent, evidence.MaxSkippedPercent)
		}
	}

	if run.Comparison == nil {
		add("the report has no comparison")
		return problems
	}
	coverage := run.Comparison.Coverage
	if coverage.Records < 0 || coverage.Compared < 0 || coverage.Compared > coverage.Records {
		add("the comparison's coverage figures are inconsistent")
	}
	if coverage.Compared < policy.minCompared() {
		add("%d record(s) compared, and at least %d are required", coverage.Compared, policy.minCompared())
	}
	if coverage.Records < summary.Replayed {
		add("the comparison saw %d record(s), but %d were replayed", coverage.Records, summary.Replayed)
	}
	return problems
}

// summaryInconsistencies checks that a run's figures agree with each other. A real run's
// always do, because every record is counted exactly once.
func summaryInconsistencies(summary *replay.Summary) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	skipped, negative := 0, false
	for _, n := range summary.Skipped {
		skipped += n
		negative = negative || n < 0
	}
	for _, n := range summary.CaptureDrops {
		negative = negative || n < 0
	}
	if negative || summary.Records < 0 || summary.Eligible < 0 || summary.Replayed < 0 || summary.NotReplayed < 0 || summary.LoadFailures < 0 {
		add("the run summary has negative counts")
	}
	if summary.Records != summary.Eligible+skipped {
		add("%d readable record(s) don't match %d eligible and %d skipped", summary.Records, summary.Eligible, skipped)
	}
	if accounted := summary.Replayed + summary.NotReplayed + summary.LoadFailures; accounted != summary.Eligible {
		add("%d eligible record(s) don't match the %d accounted for", summary.Eligible, accounted)
	}
	for _, role := range []replay.Role{replay.RoleBaselineA, replay.RoleBaselineB, replay.RoleCandidate} {
		name := role.String()
		target := summary.Targets[name]
		if target == nil {
			add("the run summary has no figures for %s", name)
			continue
		}
		var outcomes int64
		negativeOutcome := false
		for _, n := range target.Outcomes {
			outcomes += n
			negativeOutcome = negativeOutcome || n < 0
		}
		switch {
		case negativeOutcome || target.Calls < 0:
			add("%s has negative counts", name)
		case outcomes != target.Calls:
			add("%s made %d call(s), but %d outcome(s) are recorded", name, target.Calls, outcomes)
		case target.Calls < int64(summary.Replayed):
			add("%s made %d call(s) for %d replayed record(s)", name, target.Calls, summary.Replayed)
		}
	}
	return problems
}

func judgeFindings(comparison *diff.Result, policy *Policy, decision *Decision) {
	used := make([]bool, len(policy.Waivers))
	listed := make(map[diff.Severity]int)
	inconclusive := 0
	for _, stored := range comparison.Findings {
		listed[stored.Severity]++
		finding := stored
		// A finding's severity comes from what it is. A file saying otherwise can't downgrade it.
		severity, known := diff.SeverityOf(finding.Kind)
		if !known {
			decision.Problems = append(decision.Problems, fmt.Sprintf("the report holds a kind of finding this build doesn't know: %q", finding.Kind))
			decision.Findings = append(decision.Findings, JudgedFinding{Finding: finding, Disposition: DispositionInconclusive})
			decision.Inconclusive++
			continue
		}
		if severity != stored.Severity {
			decision.Problems = append(decision.Problems, fmt.Sprintf("a %s finding on %s is recorded as %q", finding.Kind, finding.Route, stored.Severity))
			finding.Severity = severity
		}
		judged := JudgedFinding{Finding: finding, Disposition: DispositionAllowed}
		switch {
		case waiverFor(finding, policy, used) != nil:
			waiver := waiverFor(finding, policy, used)
			judged.Disposition = DispositionWaived
			judged.Reason = waiver.Reason
			decision.Waived++
		case failsOn(finding, policy):
			judged.Disposition = DispositionFailed
			decision.Failed++
		case finding.Severity == diff.SeverityUncertain && !slices.Contains(policy.Evidence.AllowUncertain, string(finding.Kind)):
			inconclusive++
			if inconclusive > policy.Evidence.MaxUncertain {
				judged.Disposition = DispositionInconclusive
				decision.Inconclusive++
			}
		}
		decision.Findings = append(decision.Findings, judged)
	}
	// A reached limit means part of the evidence was never compared. Nothing in a policy can
	// accept that, since raising the limit is the fix.
	for _, notice := range comparison.Limited {
		listed[notice.Severity]++
		decision.Findings = append(decision.Findings, JudgedFinding{Finding: notice, Disposition: DispositionInconclusive})
		decision.Inconclusive++
		decision.Problems = append(decision.Problems, fmt.Sprintf("%s on %s, so part of the evidence wasn't compared", notice.Kind, notice.Route))
	}
	for i, waiver := range policy.Waivers {
		if !used[i] {
			decision.UnusedWaivers = append(decision.UnusedWaivers, waiver)
		}
	}
	if inconclusive > policy.Evidence.MaxUncertain {
		decision.Problems = append(decision.Problems, fmt.Sprintf("%d uncertain finding(s), and %d allowed", inconclusive, policy.Evidence.MaxUncertain))
	}

	// Counts cover findings the list left out. Those can't be waived or judged by kind, so a
	// severity the policy fails on counts in full, and anything else can't be called a pass.
	if comparison.Truncated.Findings < 0 {
		decision.Problems = append(decision.Problems, "the comparison's truncation figures are inconsistent")
	}
	unlisted := 0
	inconsistent := false
	for severity, count := range comparison.Counts {
		missing := count - listed[severity]
		inconsistent = inconsistent || count < 0 || missing < 0
		if missing <= 0 {
			continue
		}
		unlisted += missing
		if slices.Contains(policy.FailOn, string(severity)) {
			decision.UnlistedFailures += missing
		}
	}
	if comparison.Truncated.Findings > unlisted {
		unlisted = comparison.Truncated.Findings
	}
	if unlisted > decision.UnlistedFailures {
		decision.Problems = append(decision.Problems, fmt.Sprintf("%d finding(s) were left out of the report by a limit and couldn't be judged", unlisted))
	}
	if inconsistent {
		decision.Problems = append(decision.Problems, "the comparison's severity counts disagree with its findings")
	}
}

func failsOn(finding diff.Finding, policy *Policy) bool {
	return slices.Contains(policy.FailOn, string(finding.Severity)) || slices.Contains(policy.FailOn, string(finding.Kind))
}

// waiverFor returns the first waiver covering a finding, and notes that it was used.
func waiverFor(finding diff.Finding, policy *Policy, used []bool) *Waiver {
	for i := range policy.Waivers {
		waiver := &policy.Waivers[i]
		if waiver.Route != finding.Route || !slices.Contains(waiver.Kinds, string(finding.Kind)) {
			continue
		}
		if len(waiver.Paths) > 0 && !slices.ContainsFunc(waiver.Paths, func(rule string) bool { return diff.PathCovers(rule, finding.Path) }) {
			continue
		}
		used[i] = true
		return waiver
	}
	return nil
}
