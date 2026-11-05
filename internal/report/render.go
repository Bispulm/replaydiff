package report

import (
	"cmp"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/Bispulm/replaydiff/internal/diff"
)

// GateSchema identifies the gate's JSON output.
const GateSchema = "replaydiff.gate/v1"

// maxMarkdownRows bounds each table. CI summaries have size limits, and the JSON output
// holds everything.
const maxMarkdownRows = 100

// JSON renders the decision together with the run it judged.
func JSON(run *Run, decision *Decision) ([]byte, error) {
	data, err := json.MarshalIndent(struct {
		Schema   string    `json:"schema"`
		Decision *Decision `json:"decision"`
		Run      *Run      `json:"run"`
	}{GateSchema, decision, run}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode gate output: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteOutput saves rendered output atomically.
func WriteOutput(path string, data []byte) error { return writeFile(path, data) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func findingName(f *diff.Finding) string {
	name := string(f.Kind)
	if f.Path != "" {
		name += " " + f.Path
	}
	if f.ValueType != "" {
		name += " (" + f.ValueType + ")"
	}
	return name
}

func describeValue(v diff.Value) string {
	switch {
	case !v.Present:
		return "(missing)"
	case v.Text != "":
		return v.Text
	default:
		return "(" + v.Type + ")"
	}
}

func evidenceLines(f *diff.Finding) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s on %s, seen %d time(s)", findingName(f), f.Route, f.Count)
	if f.Detail != "" {
		fmt.Fprintf(&out, "\n%s", f.Detail)
	}
	if e := f.Evidence; e != nil {
		fmt.Fprintf(&out, "\nexample: record %s (sequence %d)", e.RecordID, e.Seq)
		if e.Field != "" {
			fmt.Fprintf(&out, ", field %s", e.Field)
		}
		fmt.Fprintf(&out, "\nbaseline A: %s\nbaseline B: %s\ncandidate: %s", describeValue(e.BaselineA), describeValue(e.BaselineB), describeValue(e.Candidate))
	}
	return out.String()
}

type xmlDetail struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr,omitempty"`
	Text    string `xml:",chardata"`
}

type xmlCase struct {
	Name      string     `xml:"name,attr"`
	ClassName string     `xml:"classname,attr"`
	Failure   *xmlDetail `xml:"failure,omitempty"`
	Error     *xmlDetail `xml:"error,omitempty"`
	Skipped   *xmlDetail `xml:"skipped,omitempty"`
}

type xmlSuite struct {
	Name     string    `xml:"name,attr"`
	Tests    int       `xml:"tests,attr"`
	Failures int       `xml:"failures,attr"`
	Errors   int       `xml:"errors,attr"`
	Skipped  int       `xml:"skipped,attr"`
	Cases    []xmlCase `xml:"testcase"`
}

type xmlSuites struct {
	XMLName  xml.Name   `xml:"testsuites"`
	Name     string     `xml:"name,attr"`
	Tests    int        `xml:"tests,attr"`
	Failures int        `xml:"failures,attr"`
	Errors   int        `xml:"errors,attr"`
	Skipped  int        `xml:"skipped,attr"`
	Suites   []xmlSuite `xml:"testsuite"`
}

func (s *xmlSuite) add(c xmlCase) {
	s.Cases = append(s.Cases, c)
	s.Tests++
	switch {
	case c.Failure != nil:
		s.Failures++
	case c.Error != nil:
		s.Errors++
	case c.Skipped != nil:
		s.Skipped++
	}
}

// JUnit renders the decision. A regression is a failure, because the code under test is at
// fault. Missing evidence is an error, because the check itself couldn't complete. A waived
// finding is skipped, with its reason. encoding/xml escapes everything, including invalid
// characters, so names taken from traffic can't change the file's structure.
func JUnit(run *Run, decision *Decision) ([]byte, error) {
	const evidenceSuite = "replaydiff evidence"
	suites := xmlSuites{Name: "replaydiff"}

	evidence := xmlSuite{Name: evidenceSuite}
	if len(decision.Problems) == 0 {
		evidence.add(xmlCase{Name: "evidence is complete", ClassName: evidenceSuite})
	}
	for _, problem := range decision.Problems {
		evidence.add(xmlCase{
			Name:      problem,
			ClassName: evidenceSuite,
			Error:     &xmlDetail{Message: problem, Type: "incomplete_evidence", Text: problem},
		})
	}
	if n := decision.UnlistedFailures; n > 0 {
		message := fmt.Sprintf("%d failing finding(s) were left out of the report by a limit", n)
		evidence.add(xmlCase{
			Name:      "failing findings left out of the report",
			ClassName: evidenceSuite,
			Failure:   &xmlDetail{Message: message, Type: "unlisted_failures", Text: message},
		})
	}
	suites.Suites = append(suites.Suites, evidence)

	byRoute := make(map[string][]JudgedFinding)
	if run.Comparison != nil {
		for _, route := range run.Comparison.Routes {
			byRoute[route.Route] = nil
		}
	}
	for _, finding := range decision.Findings {
		byRoute[finding.Route] = append(byRoute[finding.Route], finding)
	}
	for _, route := range sortedKeys(byRoute) {
		suite := xmlSuite{Name: route}
		if len(byRoute[route]) == 0 {
			suite.add(xmlCase{Name: "no findings", ClassName: route})
		}
		for i := range byRoute[route] {
			finding := &byRoute[route][i]
			c := xmlCase{Name: findingName(&finding.Finding), ClassName: route}
			text := evidenceLines(&finding.Finding)
			detail := &xmlDetail{Message: findingName(&finding.Finding), Type: string(finding.Kind), Text: text}
			switch finding.Disposition {
			case DispositionFailed:
				c.Failure = detail
			case DispositionInconclusive:
				c.Error = detail
			case DispositionWaived:
				c.Skipped = &xmlDetail{Message: "waived: " + finding.Reason, Text: text}
			case DispositionAllowed:
			}
			suite.add(c)
		}
		suites.Suites = append(suites.Suites, suite)
	}

	for i := range suites.Suites {
		suites.Tests += suites.Suites[i].Tests
		suites.Failures += suites.Suites[i].Failures
		suites.Errors += suites.Suites[i].Errors
		suites.Skipped += suites.Suites[i].Skipped
	}
	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode JUnit: %w", err)
	}
	return append([]byte(xml.Header), append(data, '\n')...), nil
}

var markdownEscaper = strings.NewReplacer(
	`\`, `\\`,
	`&`, `&amp;`,
	`<`, `&lt;`,
	`>`, `&gt;`,
	`|`, `\|`,
	"`", "\\`",
	`*`, `\*`,
	`[`, `\[`,
	`]`, `\]`,
	"\n", " ",
	"\r", " ",
)

// cell makes text from traffic safe in a Markdown table. It can't start a new block, close
// the table, or carry HTML into a pull request summary.
func cell(text string) string {
	const maxCellBytes = 200
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, text)
	if len(cleaned) > maxCellBytes {
		limit := maxCellBytes
		for limit > 0 && cleaned[limit]&0xC0 == 0x80 {
			limit--
		}
		cleaned = cleaned[:limit] + "..."
	}
	return markdownEscaper.Replace(cleaned)
}

func findingRows(w io.Writer, findings []JudgedFinding) {
	fmt.Fprintln(w, "| Severity | Kind | Route | Field | Count | Baseline A | Candidate |")
	fmt.Fprintln(w, "|---|---|---|---|---:|---|---|")
	for i, finding := range findings {
		if i == maxMarkdownRows {
			fmt.Fprintf(w, "\n%d more not shown. The JSON output has them all.\n", len(findings)-i)
			break
		}
		baseline, candidate := "", ""
		if e := finding.Evidence; e != nil {
			baseline, candidate = describeValue(e.BaselineA), describeValue(e.Candidate)
		} else if finding.Detail != "" {
			candidate = finding.Detail
		}
		path := finding.Path
		if finding.ValueType != "" {
			path += " (" + finding.ValueType + ")"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %s | %s |\n",
			finding.Severity, finding.Kind, cell(finding.Route), cell(path), finding.Count, cell(baseline), cell(candidate))
	}
	fmt.Fprintln(w)
}

func selectFindings(decision *Decision, keep func(*JudgedFinding) bool) []JudgedFinding {
	var out []JudgedFinding
	for i := range decision.Findings {
		if keep(&decision.Findings[i]) {
			out = append(out, decision.Findings[i])
		}
	}
	return out
}

// Markdown renders the decision for a pull request or job summary, with the verdict first
// and failures before anything else.
func Markdown(run *Run, decision *Decision) string {
	var w strings.Builder
	switch decision.Verdict {
	case VerdictPass:
		fmt.Fprintln(&w, "# replaydiff: Pass")
		fmt.Fprintln(&w, "\nThe evidence is complete and the candidate meets the policy.")
	case VerdictRegression:
		fmt.Fprintln(&w, "# replaydiff: Regression")
		fmt.Fprintf(&w, "\nThe candidate has %d finding(s) that fail the policy.\n", decision.Failed+decision.UnlistedFailures)
	case VerdictIncomplete:
		fmt.Fprintln(&w, "# replaydiff: Incomplete")
		fmt.Fprintln(&w, "\nThe evidence can't support a conclusion, so this isn't a pass.")
	}
	fmt.Fprintln(&w)

	failed := selectFindings(decision, func(f *JudgedFinding) bool { return f.Disposition == DispositionFailed })
	if len(failed) > 0 || decision.UnlistedFailures > 0 {
		fmt.Fprintln(&w, "## Failed")
		fmt.Fprintln(&w)
		findingRows(&w, failed)
		if decision.UnlistedFailures > 0 {
			fmt.Fprintf(&w, "%d more failing finding(s) were left out of the report by a limit.\n\n", decision.UnlistedFailures)
		}
	}
	if len(decision.Problems) > 0 {
		fmt.Fprintln(&w, "## Evidence problems")
		fmt.Fprintln(&w)
		for _, problem := range decision.Problems {
			fmt.Fprintf(&w, "- %s\n", cell(problem))
		}
		fmt.Fprintln(&w)
	}
	if inconclusive := selectFindings(decision, func(f *JudgedFinding) bool { return f.Disposition == DispositionInconclusive }); len(inconclusive) > 0 {
		fmt.Fprintln(&w, "## Inconclusive")
		fmt.Fprintln(&w)
		findingRows(&w, inconclusive)
	}
	if waived := selectFindings(decision, func(f *JudgedFinding) bool { return f.Disposition == DispositionWaived }); len(waived) > 0 {
		fmt.Fprintln(&w, "## Waived")
		fmt.Fprintln(&w)
		fmt.Fprintln(&w, "| Kind | Route | Field | Count | Reason |")
		fmt.Fprintln(&w, "|---|---|---|---:|---|")
		for i, finding := range waived {
			if i == maxMarkdownRows {
				fmt.Fprintf(&w, "\n%d more not shown.\n", len(waived)-i)
				break
			}
			fmt.Fprintf(&w, "| %s | %s | %s | %d | %s |\n", finding.Kind, cell(finding.Route), cell(finding.Path), finding.Count, cell(finding.Reason))
		}
		fmt.Fprintln(&w)
	}
	if len(decision.UnusedWaivers) > 0 {
		fmt.Fprintln(&w, "## Unused waivers")
		fmt.Fprintln(&w)
		fmt.Fprintln(&w, "These matched nothing in this run, so they may be stale.")
		fmt.Fprintln(&w)
		for _, waiver := range decision.UnusedWaivers {
			fmt.Fprintf(&w, "- %s: %s\n", cell(waiver.Route), cell(waiver.Reason))
		}
		fmt.Fprintln(&w)
	}
	if allowed := selectFindings(decision, func(f *JudgedFinding) bool {
		return f.Disposition == DispositionAllowed && f.Kind != diff.KindNoiseExplained
	}); len(allowed) > 0 {
		fmt.Fprintln(&w, "## Allowed by the policy")
		fmt.Fprintln(&w)
		findingRows(&w, allowed)
	}
	markdownCoverage(&w, run, decision)
	if run.Comparison != nil {
		markdownNoise(&w, run.Comparison)
		markdownLatency(&w, run.Comparison)
	}
	return w.String()
}

func markdownCoverage(w io.Writer, run *Run, decision *Decision) {
	fmt.Fprintln(w, "## Coverage")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Policy fails on: %s\n\n", cell(strings.Join(decision.Policy.FailOn, ", ")))
	if run.Summary == nil {
		return
	}
	summary := run.Summary
	fmt.Fprintln(w, "| Measure | Count |")
	fmt.Fprintln(w, "|---|---:|")
	fmt.Fprintf(w, "| Readable records | %d |\n", summary.Records)
	fmt.Fprintf(w, "| Eligible | %d |\n", summary.Eligible)
	fmt.Fprintf(w, "| Replayed | %d |\n", summary.Replayed)
	if run.Comparison != nil {
		fmt.Fprintf(w, "| Compared | %d |\n", run.Comparison.Coverage.Compared)
	}
	for _, reason := range sortedKeys(summary.Skipped) {
		fmt.Fprintf(w, "| Skipped: %s | %d |\n", cell(reason), summary.Skipped[reason])
	}
	for _, reason := range sortedKeys(summary.CaptureDrops) {
		fmt.Fprintf(w, "| Dropped at capture: %s | %d |\n", cell(reason), summary.CaptureDrops[reason])
	}
	for _, role := range sortedKeys(summary.Targets) {
		if n := summary.Targets[role].Resends; n > 0 {
			fmt.Fprintf(w, "| Resent by the HTTP client: %s | %d |\n", cell(role), n)
		}
	}
	fmt.Fprintln(w)
}

func markdownNoise(w io.Writer, comparison *diff.Result) {
	if len(comparison.Noise) == 0 && len(comparison.Ignored) == 0 {
		return
	}
	fmt.Fprintln(w, "## Noise")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Noise explains differences in values only. Removed and retyped fields are always reported.")
	fmt.Fprintln(w)
	if len(comparison.Noise) > 0 {
		fmt.Fprintln(w, "| Route | Field | Type | Decision | Compared | Baselines differ | Candidate differs |")
		fmt.Fprintln(w, "|---|---|---|---|---:|---:|---:|")
		for i, noise := range comparison.Noise {
			if i == maxMarkdownRows {
				fmt.Fprintf(w, "\n%d more not shown.\n", len(comparison.Noise)-i)
				break
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %.0f%% | %.0f%% |\n",
				cell(noise.Route), cell(noise.Path), cell(noise.Type), noise.Decision, noise.Observations, noise.BaselineRate*100, noise.CandidateRate*100)
		}
		fmt.Fprintln(w)
	}
	for _, ignored := range comparison.Ignored {
		fmt.Fprintf(w, "- Ignored by a rule: %s %s (%d)\n", cell(ignored.Route), cell(ignored.Path), ignored.Count)
	}
	if len(comparison.Ignored) > 0 {
		fmt.Fprintln(w)
	}
}

func markdownLatency(w io.Writer, comparison *diff.Result) {
	var rows []string
	skipped := 0
	for _, route := range comparison.Routes {
		if !route.Latency.Evaluated {
			skipped++
			continue
		}
		for _, row := range route.Latency.Percentiles {
			rows = append(rows, fmt.Sprintf("| %s | p%s | %.1f | %.1f | %.1f | %.0f%% |", cell(route.Route),
				strconv.FormatFloat(row.Percentile, 'f', -1, 64),
				float64(row.BaselineAMicros)/1000, float64(row.BaselineBMicros)/1000, float64(row.CandidateMicros)/1000, row.IncreasePercent))
		}
	}
	if len(rows) == 0 && skipped == 0 {
		return
	}
	fmt.Fprintln(w, "## Latency")
	fmt.Fprintln(w)
	if len(rows) > 0 {
		fmt.Fprintln(w, "Nearest-rank percentiles in milliseconds, compared with the slower baseline.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Route | Percentile | Baseline A | Baseline B | Candidate | Increase |")
		fmt.Fprintln(w, "|---|---|---:|---:|---:|---:|")
		for i, row := range rows {
			if i == maxMarkdownRows {
				fmt.Fprintf(w, "\n%d more not shown.\n", len(rows)-i)
				break
			}
			fmt.Fprintln(w, row)
		}
		fmt.Fprintln(w)
	}
	if skipped > 0 {
		fmt.Fprintf(w, "%d route(s) had too few samples for latency to be evaluated.\n\n", skipped)
	}
}

// Text renders the decision for a terminal.
func Text(w io.Writer, run *Run, decision *Decision) {
	fmt.Fprintf(w, "verdict: %s\n", decision.Verdict)
	if summary := run.Summary; summary != nil {
		fmt.Fprintf(w, "records: %d readable, %d eligible, %d replayed\n", summary.Records, summary.Eligible, summary.Replayed)
		for _, reason := range sortedKeys(summary.Skipped) {
			fmt.Fprintf(w, "skipped: %d %s\n", summary.Skipped[reason], reason)
		}
		for _, reason := range sortedKeys(summary.CaptureDrops) {
			fmt.Fprintf(w, "capture dropped: %d %s\n", summary.CaptureDrops[reason], reason)
		}
		for _, role := range sortedKeys(summary.Targets) {
			target := summary.Targets[role]
			var statuses []string
			for _, class := range sortedKeys(target.Statuses) {
				statuses = append(statuses, fmt.Sprintf("%s=%d", class, target.Statuses[class]))
			}
			fmt.Fprintf(w, "%s: %d call(s) %s\n", role, target.Calls, strings.Join(statuses, " "))
		}
	}
	for _, problem := range decision.Problems {
		fmt.Fprintf(w, "problem: %s\n", problem)
	}
	comparison := run.Comparison
	if comparison == nil {
		return
	}
	fmt.Fprintf(w, "compared: %d of %d records\n", comparison.Coverage.Compared, comparison.Coverage.Records)
	fmt.Fprintf(w, "findings: %d breaking, %d warning, %d uncertain, %d info\n",
		comparison.Counts[diff.SeverityBreaking], comparison.Counts[diff.SeverityWarning],
		comparison.Counts[diff.SeverityUncertain], comparison.Counts[diff.SeverityInfo])
	// Most important first: a stable sort keeps the severity order within each group.
	findings := slices.Clone(decision.Findings)
	rank := func(d Disposition) int {
		switch d {
		case DispositionFailed:
			return 0
		case DispositionInconclusive:
			return 1
		case DispositionWaived:
			return 2
		default:
			return 3
		}
	}
	slices.SortStableFunc(findings, func(x, y JudgedFinding) int { return cmp.Compare(rank(x.Disposition), rank(y.Disposition)) })
	for _, finding := range findings {
		fmt.Fprintf(w, "%-12s %-9s %-26s %s", finding.Disposition, finding.Severity, finding.Kind, finding.Route)
		if finding.Path != "" {
			fmt.Fprintf(w, " %s", finding.Path)
		}
		fmt.Fprintf(w, " (%d)", finding.Count)
		switch {
		case finding.Reason != "":
			fmt.Fprintf(w, ": %s", finding.Reason)
		case finding.Detail != "":
			fmt.Fprintf(w, ": %s", finding.Detail)
		}
		fmt.Fprintln(w)
	}
	for _, ignored := range comparison.Ignored {
		fmt.Fprintf(w, "ignored by rule: %s %s (%d)\n", ignored.Route, ignored.Path, ignored.Count)
	}
	if n := comparison.Truncated.Findings; n > 0 {
		fmt.Fprintf(w, "%d more finding(s) left out; the counts above include them\n", n)
	}
	for _, waiver := range decision.UnusedWaivers {
		fmt.Fprintf(w, "unused waiver: %s: %s\n", waiver.Route, waiver.Reason)
	}
}
