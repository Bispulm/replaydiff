package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/Bispulm/replaydiff/internal/diff"
	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/replay"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// reportSchema identifies the run report format.
const reportSchema = "replaydiff.run/v1"

// verdictNotEvaluated says no CI policy has judged the findings yet. Keeping it in
// the report means nobody can mistake a completed run for a passed check.
const verdictNotEvaluated = "not_evaluated"

const runUsage = `Usage: replaydiff run --traffic DIR --redact FILE --report FILE
                      --baseline-a URL --baseline-b URL --candidate URL
                      --allow-origin URL [--allow-origin URL ...] [flags]

Replay eligible records against both baselines and the candidate, and compare the
responses. Only GET, HEAD and OPTIONS are eligible unless --allow-method says
otherwise. replaydiff makes one attempt per target, and redirects aren't followed.

Exit codes:
  0  the replay finished with complete evidence, whatever the findings were
  2  invalid configuration, execution failure, or incomplete evidence

`

// runReport is the file written by run and read by report.
type runReport struct {
	Schema           string                 `json:"schema"`
	Verdict          string                 `json:"verdict"`
	EvidenceComplete bool                   `json:"evidence_complete"`
	Problems         []string               `json:"problems,omitempty"`
	Config           reportConfig           `json:"config"`
	Summary          *replay.Summary        `json:"summary"`
	Comparison       *diff.Result           `json:"comparison,omitempty"`
	Samples          []*replay.RecordResult `json:"samples,omitempty"`
}

// reportConfig records run settings. Credential values are deliberately absent:
// it names only the headers each target was given.
type reportConfig struct {
	Targets              map[string]string   `json:"targets"`
	CredentialHeaders    map[string][]string `json:"credential_headers,omitempty"`
	AllowMethods         []string            `json:"allow_methods,omitempty"`
	RecordsPerSecond     float64             `json:"records_per_second"`
	TargetCallsPerSecond float64             `json:"target_calls_per_second,omitempty"`
	Concurrency          int                 `json:"concurrency"`
	PerTargetConcurrency int                 `json:"per_target_concurrency"`
	MaxActiveSessions    int                 `json:"max_active_sessions"`
	TimeoutSeconds       float64             `json:"timeout_seconds"`
}

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func runRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var origins, methods, credentials stringList
	maxResponse := byteSize(replay.DefaultMaxResponseBytes)
	var cfg replay.Config

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir := fs.String("traffic", "", "directory of traffic segments (required)")
	baselineA := fs.String("baseline-a", "", "first baseline origin (required)")
	baselineB := fs.String("baseline-b", "", "second baseline origin, running the same version as the first (required)")
	candidate := fs.String("candidate", "", "candidate origin (required)")
	reportPath := fs.String("report", "", "file to write the run report to (required)")
	policyPath := fs.String("redact", "", "redaction policy applied to responses before comparing them, because their values can appear in the report (required)")
	diffConfig := fs.String("diff-config", "", "comparison rules; see docs/diffing.md")
	maxSamples := fs.Int("max-samples", 100, "most record outcomes to include in the report")
	maxRecords := fs.Int("max-records", traffic.DefaultMaxRecords, "fail if the dataset holds more records than this")
	fs.Var(&origins, "allow-origin", "origin replay may send to; every target must be listed (required, repeatable)")
	fs.Var(&methods, "allow-method", "method to replay besides GET, HEAD and OPTIONS; this repeats its side effects (repeatable)")
	fs.Var(&credentials, "target-credential", "ROLE:Header=ENV_VAR sets a header on one target from an environment variable (repeatable)")
	fs.Float64Var(&cfg.RecordsPerSecond, "rps", 50, "logical records started per second, each making three calls")
	fs.Float64Var(&cfg.TargetCallsPerSecond, "target-rps", 0, "calls per second to each target; 0 means no limit")
	fs.IntVar(&cfg.Concurrency, "concurrency", replay.DefaultConcurrency, "in-flight calls across all targets")
	fs.IntVar(&cfg.PerTargetConcurrency, "per-target-concurrency", replay.DefaultPerTargetConcurrency, "in-flight calls to each target")
	fs.IntVar(&cfg.MaxActiveSessions, "max-active-sessions", replay.DefaultMaxActiveSessions, "sessions worked on at once")
	fs.DurationVar(&cfg.Timeout, "timeout", replay.DefaultTimeout, "time allowed for one call")
	fs.Var(&maxResponse, "max-response-body", "largest response body to hold")
	fs.BoolVar(&cfg.H2C, "target-h2c", false, "use HTTP/2 without TLS for all targets, with no fallback; for development")
	targetCA := fs.String("target-ca-file", "", "PEM certificates to trust for https targets, instead of the system roots")
	fs.Usage = func() {
		fmt.Fprint(stderr, runUsage)
		fs.PrintDefaults()
	}
	help, err := parseFlags(fs, args, stderr)
	if help {
		return ExitOK
	}
	if err != nil {
		return fail(stderr, "run", err)
	}
	for _, required := range []struct{ name, value string }{
		{"traffic", *dir}, {"redact", *policyPath}, {"baseline-a", *baselineA}, {"baseline-b", *baselineB}, {"candidate", *candidate}, {"report", *reportPath},
	} {
		if required.value == "" {
			return fail(stderr, "run", fmt.Errorf("--%s is required", required.name))
		}
	}
	if len(origins) == 0 {
		return fail(stderr, "run", errors.New("--allow-origin is required: list every origin replay may send to"))
	}

	cfg.BaselineA = replay.TargetConfig{URL: *baselineA}
	cfg.BaselineB = replay.TargetConfig{URL: *baselineB}
	cfg.Candidate = replay.TargetConfig{URL: *candidate}
	cfg.AllowedOrigins = origins
	cfg.AllowMethods = methods
	cfg.MaxResponseBytes = int64(maxResponse)
	credentialHeaders, err := applyCredentials(&cfg, credentials)
	if err != nil {
		return fail(stderr, "run", err)
	}
	cfg.TLS, err = loadCAFile("target-ca-file", *targetCA)
	if err != nil {
		return fail(stderr, "run", err)
	}

	policy, err := redact.LoadPolicy(*policyPath)
	if err != nil {
		return fail(stderr, "run", err)
	}
	sanitizer, err := redact.NewEngine(policy, redact.Options{})
	if err != nil {
		return fail(stderr, "run", err)
	}
	defer sanitizer.Close()
	comparisonConfig, err := diff.LoadConfig(*diffConfig)
	if err != nil {
		return fail(stderr, "run", err)
	}
	comparator, err := diff.New(comparisonConfig, sanitizer)
	if err != nil {
		return fail(stderr, "run", err)
	}

	// Targets are checked before the dataset is opened, so a bad target can't
	// have any effect.
	engine, err := replay.New(cfg)
	if err != nil {
		return fail(stderr, "run", err)
	}
	defer engine.Close()

	dataset, err := traffic.Scan(*dir, traffic.ScanOptions{MaxRecords: *maxRecords})
	if err != nil {
		return fail(stderr, "run", err)
	}
	defer func() { _ = dataset.Close() }()

	samples := newSampleSet(*maxSamples)
	summary, err := engine.Run(ctx, dataset, func(result *replay.RecordResult) {
		// The comparator goes first, because adding a sample drops the response data.
		comparator.Observe(result)
		samples.add(result)
	})
	if err != nil {
		return fail(stderr, "run", err)
	}
	comparison := comparator.Result()

	report := &runReport{
		Schema:           reportSchema,
		Verdict:          verdictNotEvaluated,
		EvidenceComplete: summary.Complete(),
		Problems:         summary.Problems(),
		Config: reportConfig{
			Targets:              map[string]string{"baseline-a": *baselineA, "baseline-b": *baselineB, "candidate": *candidate},
			CredentialHeaders:    credentialHeaders,
			AllowMethods:         methods,
			RecordsPerSecond:     cfg.RecordsPerSecond,
			TargetCallsPerSecond: cfg.TargetCallsPerSecond,
			Concurrency:          cfg.Concurrency,
			PerTargetConcurrency: cfg.PerTargetConcurrency,
			MaxActiveSessions:    cfg.MaxActiveSessions,
			TimeoutSeconds:       cfg.Timeout.Seconds(),
		},
		Summary:    summary,
		Comparison: comparison,
		Samples:    samples.sorted(),
	}
	if err := writeReport(*reportPath, report); err != nil {
		return fail(stderr, "run", err)
	}

	fmt.Fprintf(stdout, "replayed %d of %d eligible record(s), %d skipped, %d upstream call(s) in %.2fs\n",
		summary.Replayed, summary.Eligible, summary.Records-summary.Eligible, summary.UpstreamCalls, summary.DurationSeconds)
	fmt.Fprintf(stdout, "findings: %d breaking, %d warning, %d uncertain, %d info\n",
		comparison.Counts[diff.SeverityBreaking], comparison.Counts[diff.SeverityWarning],
		comparison.Counts[diff.SeverityUncertain], comparison.Counts[diff.SeverityInfo])
	fmt.Fprintf(stdout, "report: %s\n", *reportPath)
	for _, reason := range sortedKeys(summary.CaptureDrops) {
		fmt.Fprintf(stderr, "warning: capture dropped %d exchange(s): %s\n", summary.CaptureDrops[reason], reason)
	}
	for _, role := range sortedKeys(summary.Targets) {
		if n := summary.Targets[role].Resends; n > 0 {
			fmt.Fprintf(stderr, "warning: %s: the HTTP client resent %d request(s) the server said it hadn't processed\n", role, n)
		}
	}
	// A reached limit means part of the evidence wasn't compared. It stays out of the
	// report's problems so that CI policy can decide how to treat it.
	for _, notice := range comparison.Limited {
		fmt.Fprintf(stderr, "incomplete: %s on %s: %s\n", notice.Kind, notice.Route, notice.Detail)
	}
	if !report.EvidenceComplete || len(comparison.Limited) > 0 {
		for _, problem := range report.Problems {
			fmt.Fprintf(stderr, "incomplete: %s\n", problem)
		}
		return ExitFailure
	}
	fmt.Fprintln(stderr, "note: this exit code covers the evidence, not the findings; no CI policy is applied yet")
	return ExitOK
}

// applyCredentials reads ROLE:Header=ENV_VAR specs into the target configs and
// returns which headers each role received. Values come only from the
// environment, so they don't appear in process listings or recordings.
func applyCredentials(cfg *replay.Config, specs []string) (map[string][]string, error) {
	targets := map[string]*replay.TargetConfig{
		"baseline-a": &cfg.BaselineA,
		"baseline-b": &cfg.BaselineB,
		"candidate":  &cfg.Candidate,
	}
	names := make(map[string][]string)
	for _, spec := range specs {
		role, rest, ok := strings.Cut(spec, ":")
		header, envName, ok2 := strings.Cut(rest, "=")
		if !ok || !ok2 || header == "" || envName == "" {
			return nil, errors.New("--target-credential: want ROLE:Header=ENV_VAR")
		}
		target := targets[role]
		if target == nil {
			return nil, fmt.Errorf("--target-credential: unknown role %q: want baseline-a, baseline-b or candidate", role)
		}
		value, found := os.LookupEnv(envName)
		if !found || value == "" {
			return nil, fmt.Errorf("--target-credential: %s is not set", envName)
		}
		if target.Headers == nil {
			target.Headers = make(http.Header)
		}
		target.Headers.Set(header, value)
		names[role] = append(names[role], http.CanonicalHeaderKey(header))
	}
	return names, nil
}

// sampleSet keeps the results with the lowest sequence numbers, so a report's
// contents don't depend on the order concurrent workers finished in.
type sampleSet struct {
	mu    sync.Mutex
	limit int
	items []*replay.RecordResult
}

func newSampleSet(limit int) *sampleSet { return &sampleSet{limit: max(limit, 0)} }

func compareSamples(a, b *replay.RecordResult) int {
	if a.Seq != b.Seq {
		if a.Seq < b.Seq {
			return -1
		}
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}

func (s *sampleSet) add(result *replay.RecordResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	position, _ := slices.BinarySearchFunc(s.items, result, compareSamples)
	if position >= s.limit {
		return
	}
	// Dropping response data keeps the set bounded in memory and out of reports.
	for i := range result.Calls {
		result.Calls[i].Body = nil
		result.Calls[i].Header = nil
	}
	s.items = slices.Insert(s.items, position, result)
	if len(s.items) > s.limit {
		s.items = s.items[:s.limit]
	}
}

func (s *sampleSet) sorted() []*replay.RecordResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items
}

// writeReport writes atomically, so a crash can't leave a partial report that a
// later step mistakes for a complete one. The file is readable only by its owner.
func writeReport(path string, report *runReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".replaydiff-report-*")
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	if _, err := temp.Write(append(data, '\n')); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write report: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
