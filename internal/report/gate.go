package report

import (
	"fmt"
	"slices"

	"github.com/Bispulm/replaydiff/internal/diff"
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

// Evaluate applies a policy to a run. Evidence is judged from the raw figures instead of
// the run's own claim, so an edited or stale file can't pass by saying it's complete.
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
	// Both sources count. The recomputed one can't be talked out of a problem by an edited
	// file, and the stored one holds anything only the run itself could see.
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
	if coverage.Compared < policy.minCompared() {
		add("%d record(s) compared, and at least %d are required", coverage.Compared, policy.minCompared())
	}
	if coverage.Records < summary.Replayed {
		add("the comparison saw %d record(s), but %d were replayed", coverage.Records, summary.Replayed)
	}
	return problems
}

func judgeFindings(comparison *diff.Result, policy *Policy, decision *Decision) {
	used := make([]bool, len(policy.Waivers))
	listed := make(map[diff.Severity]int)
	inconclusive := 0
	for _, finding := range slices.Concat(comparison.Findings, comparison.Limited) {
		listed[finding.Severity]++
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
	for i, waiver := range policy.Waivers {
		if !used[i] {
			decision.UnusedWaivers = append(decision.UnusedWaivers, waiver)
		}
	}
	if decision.Inconclusive > 0 {
		decision.Problems = append(decision.Problems, fmt.Sprintf("%d uncertain finding(s), and %d allowed", inconclusive, policy.Evidence.MaxUncertain))
	}

	// Counts cover findings the list left out. Those can't be waived or judged by kind, so a
	// severity the policy fails on counts in full, and anything else can't be called a pass.
	unlisted := 0
	for severity, count := range comparison.Counts {
		missing := count - listed[severity]
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
