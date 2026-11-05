package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Bispulm/replaydiff/internal/report"
)

const reportUsage = `Usage: replaydiff report FILE [flags]

Apply the CI policy to a run report, print the outcome, and optionally write it in
other formats. See docs/ci.md.

Exit codes:
  0  pass: the evidence is complete and the candidate meets the policy
  1  regression: a finding fails the policy
  2  incomplete: invalid input, a failure, or evidence that can't support a conclusion

A confirmed regression exits 1 even if some evidence is also missing.

`

func runReportCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy file; the default fails on breaking findings and any uncertainty")
	failOn := fs.String("fail-on", "", "comma-separated severities and kinds that fail, overriding the policy")
	jsonPath := fs.String("json", "", "write the decision and run as JSON to this file")
	junitPath := fs.String("junit", "", "write JUnit XML to this file")
	markdownPath := fs.String("markdown", "", "write Markdown to this file")
	quiet := fs.Bool("quiet", false, "print only the verdict")
	fs.Usage = func() {
		fmt.Fprint(stderr, reportUsage)
		fs.PrintDefaults()
	}

	// The file may come before the flags, which the flag package doesn't handle itself.
	var file string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return fail(stderr, "report", err)
	}
	switch {
	case file == "" && fs.NArg() == 1:
		file = fs.Arg(0)
	case file == "" || fs.NArg() != 0:
		fs.Usage()
		return ExitFailure
	}

	policy, err := report.LoadPolicy(*policyPath)
	if err != nil {
		return fail(stderr, "report", err)
	}
	if *failOn != "" {
		if err := policy.SetFailOn(*failOn); err != nil {
			return fail(stderr, "report", err)
		}
	}
	run, err := report.Load(file)
	if err != nil {
		return fail(stderr, "report", err)
	}
	decision := report.Evaluate(run, policy)

	// Output comes first, so that a failed build still has its explanation. If it can't be
	// written, the step failed and nothing can be called a pass.
	if err := writeOutputs(run, decision, *jsonPath, *junitPath, *markdownPath); err != nil {
		return fail(stderr, "report", err)
	}
	if *quiet {
		fmt.Fprintf(stdout, "verdict: %s\n", decision.Verdict)
	} else {
		report.Text(stdout, run, decision)
	}
	return decision.ExitCode
}

func writeOutputs(run *report.Run, decision *report.Decision, jsonPath, junitPath, markdownPath string) error {
	if jsonPath != "" {
		data, err := report.JSON(run, decision)
		if err != nil {
			return err
		}
		if err := report.WriteOutput(jsonPath, data); err != nil {
			return err
		}
	}
	if junitPath != "" {
		data, err := report.JUnit(run, decision)
		if err != nil {
			return err
		}
		if err := report.WriteOutput(junitPath, data); err != nil {
			return err
		}
	}
	if markdownPath != "" {
		if err := report.WriteOutput(markdownPath, []byte(report.Markdown(run, decision))); err != nil {
			return err
		}
	}
	return nil
}
