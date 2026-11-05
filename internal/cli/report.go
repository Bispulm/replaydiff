package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/Bispulm/replaydiff/internal/diff"
)

const reportUsage = `Usage: replaydiff report FILE

Print a summary of a run report and its findings.

There is no CI policy yet to judge the findings, so this command always exits 2,
which means a CI job can't pass on findings nobody judged.

`

func runReportCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(stderr, reportUsage)
		fs.PrintDefaults()
	}
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return fail(stderr, "report", err)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return ExitFailure
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fail(stderr, "report", err)
	}
	var report runReport
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		return fail(stderr, "report", fmt.Errorf("read report: %w", err))
	}
	if report.Schema != reportSchema {
		return fail(stderr, "report", fmt.Errorf("unsupported report schema %q: this build reads %s", report.Schema, reportSchema))
	}
	if report.Summary == nil {
		return fail(stderr, "report", errors.New("report has no summary"))
	}

	summary := report.Summary
	fmt.Fprintf(stdout, "verdict: %s\n", report.Verdict)
	fmt.Fprintf(stdout, "evidence complete: %t\n", report.EvidenceComplete)
	fmt.Fprintf(stdout, "records: %d readable, %d eligible, %d replayed\n", summary.Records, summary.Eligible, summary.Replayed)
	for _, reason := range sortedKeys(summary.Skipped) {
		fmt.Fprintf(stdout, "skipped: %d %s\n", summary.Skipped[reason], reason)
	}
	for _, reason := range sortedKeys(summary.CaptureDrops) {
		fmt.Fprintf(stdout, "capture dropped: %d %s\n", summary.CaptureDrops[reason], reason)
	}
	for _, role := range sortedKeys(summary.Targets) {
		target := summary.Targets[role]
		var statuses []string
		for _, class := range sortedKeys(target.Statuses) {
			statuses = append(statuses, fmt.Sprintf("%s=%d", class, target.Statuses[class]))
		}
		fmt.Fprintf(stdout, "%s: %d call(s) %s\n", role, target.Calls, strings.Join(statuses, " "))
	}
	for _, problem := range report.Problems {
		fmt.Fprintf(stdout, "problem: %s\n", problem)
	}
	printComparison(stdout, report.Comparison)
	fmt.Fprintln(stderr, "replaydiff report: no CI policy is applied yet, so no verdict can be given")
	return ExitFailure
}

func printComparison(w io.Writer, comparison *diff.Result) {
	if comparison == nil {
		return
	}
	fmt.Fprintf(w, "compared: %d of %d records\n", comparison.Coverage.Compared, comparison.Coverage.Records)
	fmt.Fprintf(w, "findings: %d breaking, %d warning, %d uncertain, %d info\n",
		comparison.Counts[diff.SeverityBreaking], comparison.Counts[diff.SeverityWarning],
		comparison.Counts[diff.SeverityUncertain], comparison.Counts[diff.SeverityInfo])
	for _, finding := range slices.Concat(comparison.Findings, comparison.Limited) {
		fmt.Fprintf(w, "%-9s %-26s %s", finding.Severity, finding.Kind, finding.Route)
		if finding.Path != "" {
			fmt.Fprintf(w, " %s", finding.Path)
		}
		fmt.Fprintf(w, " (%d)", finding.Count)
		if finding.Detail != "" {
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
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
