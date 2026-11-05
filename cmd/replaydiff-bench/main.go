// Command replaydiff-bench measures capture and replay against the targets in
// docs/benchmarks.md, and writes results.json and results.md to --out. It is a
// development tool and isn't part of a release.
//
//	go build -o bin/ ./cmd/... && bin/replaydiff-bench --capture bin/replaydiff
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// settings are the workloads. Quick ones are for checking the harness, not for results.
type settings struct {
	Rate, DropRate          float64
	Phase, DropPhase, Step  time.Duration
	Rounds, Connections     int
	BodyBytes               int
	Steps                   []float64
	ReplayRecords           int
	FairLong, FairShort, FE int
}

var full = settings{
	Rate: 500, DropRate: 1000, Phase: 30 * time.Second, DropPhase: 60 * time.Second, Step: 20 * time.Second,
	Rounds: 3, Connections: 16, BodyBytes: 1024, Steps: []float64{1000, 2000, 4000, 8000, 16000},
	ReplayRecords: 3000, FairLong: 1000, FairShort: 50, FE: 5,
}

var quick = settings{
	Rate: 100, DropRate: 200, Phase: time.Second, DropPhase: 2 * time.Second, Step: time.Second,
	Rounds: 1, Connections: 4, BodyBytes: 1024, Steps: []float64{100, 200},
	ReplayRecords: 100, FairLong: 100, FairShort: 10, FE: 5,
}

// Results holds every measurement, with the conditions it was taken under.
type Results struct {
	Ran         []string       `json:"measured"`
	Environment Environment    `json:"environment"`
	Settings    settings       `json:"settings"`
	Latency     []LatencyRound `json:"latency_rounds"`
	Drops       DropRun        `json:"drops"`
	Steps       []Step         `json:"steps"`
	Replay      ReplayResult   `json:"replay"`
	Fairness    FairnessResult `json:"fairness"`
}

// LatencyRound is one direct phase and one proxied phase at the same rate.
type LatencyRound struct {
	Direct     Phase   `json:"direct"`
	Proxied    Phase   `json:"proxied"`
	AddedP50ms float64 `json:"added_p50_ms"`
	AddedP99ms float64 `json:"added_p99_ms"`
}

// DropRun is sustained load through capture, and what capture recorded.
type DropRun struct {
	Phase   Phase        `json:"phase"`
	Capture CaptureStats `json:"capture"`
}

// Step is one rate in the search for the highest sustainable recording rate.
type Step struct {
	Direct      Phase        `json:"direct"`
	Proxied     Phase        `json:"proxied"`
	Capture     CaptureStats `json:"capture"`
	Sustainable bool         `json:"sustainable"`
}

func main() { os.Exit(start()) }

func start() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replaydiff-bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	binary := fs.String("capture", "bin/replaydiff", "the replaydiff binary to measure")
	out := fs.String("out", ".bench", "directory for results.json and results.md")
	short := fs.Bool("quick", false, "tiny workloads, to check the harness rather than measure")
	only := fs.String("only", "", "run one measurement: latency, drops, steps, replay or fairness")
	rounds := fs.Int("rounds", 0, "latency rounds, if not the default")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := full
	if *short {
		cfg = quick
	}
	if *rounds > 0 {
		cfg.Rounds = *rounds
	}
	selected := []string{"latency", "drops", "steps", "replay", "fairness"}
	if *only != "" {
		if !slices.Contains(selected, *only) {
			fmt.Fprintf(stderr, "--only: unknown measurement %q\n", *only)
			return 2
		}
		selected = []string{*only}
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	results, err := measure(ctx, cfg, *binary, selected, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "replaydiff-bench:", err)
		return 2
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	markdown := results.Markdown()
	if err := errors.Join(os.WriteFile(filepath.Join(*out, "results.json"), append(data, '\n'), 0o644),
		os.WriteFile(filepath.Join(*out, "results.md"), []byte(markdown), 0o644)); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprint(stdout, markdown)
	return 0
}

func measure(ctx context.Context, cfg settings, binary string, selected []string, log io.Writer) (*Results, error) {
	work, err := os.MkdirTemp("", "replaydiff-bench-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(work) }()
	upstream, closeUpstream, err := startUpstream(cfg.BodyBytes)
	if err != nil {
		return nil, err
	}
	defer closeUpstream()
	results := &Results{Settings: cfg, Environment: environment(), Ran: selected}
	want := func(name string) bool { return slices.Contains(selected, name) }
	results.Environment.LoadBefore = loadAverage()

	capture := func(name string) (*captureProcess, error) {
		dir := filepath.Join(work, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		return startCapture(binary, upstream, dir)
	}

	if want("latency") {
		if err := measureLatency(ctx, cfg, upstream, capture, results, log); err != nil {
			return nil, err
		}
	}
	if want("drops") {
		fmt.Fprintln(log, "drops: sustained load through capture")
		proc, err := capture("drops")
		if err != nil {
			return nil, err
		}
		results.Drops.Phase = openLoop(ctx, proc.proxy, cfg.DropRate, cfg.DropPhase, cfg.Connections)
		results.Drops.Phase.Target = "proxied"
		if results.Drops.Capture, err = proc.stop(); err != nil {
			return nil, err
		}
	}
	if want("steps") {
		if err := measureSteps(ctx, cfg, upstream, capture, results, log); err != nil {
			return nil, err
		}
	}
	if want("replay") {
		fmt.Fprintln(log, "replay rate")
		if results.Replay, err = measureReplay(ctx, work, cfg.ReplayRecords); err != nil {
			return nil, err
		}
	}
	if want("fairness") {
		fmt.Fprintln(log, "fairness")
		if results.Fairness, err = measureFairness(ctx, work, cfg.FairLong, cfg.FairShort, cfg.FE); err != nil {
			return nil, err
		}
	}
	results.Environment.LoadAfter = loadAverage()
	return results, ctx.Err()
}

type startFunc func(name string) (*captureProcess, error)

func measureLatency(ctx context.Context, cfg settings, upstream string, capture startFunc, results *Results, log io.Writer) error {
	fmt.Fprintln(log, "latency: direct and proxied phases")
	proc, err := capture("latency")
	if err != nil {
		return err
	}
	// A short warm-up of each, discarded.
	openLoop(ctx, upstream, cfg.Rate, cfg.Phase/10+time.Second, cfg.Connections)
	openLoop(ctx, proc.proxy, cfg.Rate, cfg.Phase/10+time.Second, cfg.Connections)
	for range cfg.Rounds {
		direct := openLoop(ctx, upstream, cfg.Rate, cfg.Phase, cfg.Connections)
		proxied := openLoop(ctx, proc.proxy, cfg.Rate, cfg.Phase, cfg.Connections)
		direct.Target, proxied.Target = "direct", "proxied"
		results.Latency = append(results.Latency, LatencyRound{Direct: direct, Proxied: proxied,
			AddedP50ms: proxied.P50 - direct.P50, AddedP99ms: proxied.P99 - direct.P99})
	}
	_, err = proc.stop()
	return err
}

func measureSteps(ctx context.Context, cfg settings, upstream string, capture startFunc, results *Results, log io.Writer) error {
	for i, rate := range cfg.Steps {
		fmt.Fprintf(log, "steps: %.0f/s\n", rate)
		proc, err := capture("step-" + strconv.Itoa(i))
		if err != nil {
			return err
		}
		step := Step{Direct: openLoop(ctx, upstream, rate, cfg.Step, cfg.Connections)}
		step.Proxied = openLoop(ctx, proc.proxy, rate, cfg.Step, cfg.Connections)
		step.Direct.Target, step.Proxied.Target = "direct", "proxied"
		if step.Capture, err = proc.stop(); err != nil {
			return err
		}
		step.Sustainable = step.Capture.DroppedTotal() == 0 && step.Proxied.Errors == 0 &&
			step.Proxied.Achieved >= 0.95*rate && step.Proxied.P99-step.Direct.P99 <= 10
		results.Steps = append(results.Steps, step)
		if !step.Sustainable {
			break
		}
	}
	return nil
}

// Environment is what the numbers depend on.
type Environment struct {
	Commit     string `json:"commit"`
	GoVersion  string `json:"go_version"`
	OS         string `json:"os"`
	CPU        string `json:"cpu"`
	CPUs       int    `json:"cpus"`
	MemoryGiB  int64  `json:"memory_gib"`
	LoadBefore string `json:"load_average_before"`
	LoadAfter  string `json:"load_average_after"`
	Started    string `json:"started"`
}

func environment() Environment {
	env := Environment{GoVersion: runtime.Version(), OS: runtime.GOOS + "/" + runtime.GOARCH, CPUs: runtime.NumCPU(), Started: time.Now().UTC().Format(time.RFC3339)}
	env.Commit = output("git", "rev-parse", "--short", "HEAD")
	if output("git", "status", "--porcelain", "--untracked-files=no") != "" {
		env.Commit += "-dirty"
	}
	switch runtime.GOOS {
	case "darwin":
		env.CPU = output("sysctl", "-n", "machdep.cpu.brand_string")
		if bytes, err := strconv.ParseInt(output("sysctl", "-n", "hw.memsize"), 10, 64); err == nil {
			env.MemoryGiB = bytes >> 30
		}
	case "linux":
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for line := range strings.Lines(string(data)) {
				if name, ok := strings.CutPrefix(line, "model name"); ok {
					env.CPU = strings.TrimSpace(strings.TrimLeft(name, "\t :"))
					break
				}
			}
		}
	}
	return env
}

func loadAverage() string {
	if runtime.GOOS == "linux" {
		data, _ := os.ReadFile("/proc/loadavg")
		return strings.Join(strings.Fields(string(data))[:min(3, len(strings.Fields(string(data))))], " ")
	}
	return strings.Trim(output("sysctl", "-n", "vm.loadavg"), "{ }")
}

func output(name string, args ...string) string {
	out, err := exec.CommandContext(context.Background(), name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Markdown summarizes the results against the targets in docs/benchmarks.md.
func (r *Results) Markdown() string {
	var b strings.Builder
	verdict := func(ok bool) string {
		if ok {
			return "met"
		}
		return "**missed**"
	}
	fmt.Fprintf(&b, "Commit `%s`, %s, %s, %d CPUs, %d GiB, %s. Load average before %s, after %s.\n\n",
		r.Environment.Commit, r.Environment.CPU, r.Environment.OS, r.Environment.CPUs, r.Environment.MemoryGiB, r.Environment.GoVersion,
		r.Environment.LoadBefore, r.Environment.LoadAfter)

	added50, added99 := []float64{}, []float64{}
	for _, round := range r.Latency {
		added50, added99 = append(added50, round.AddedP50ms), append(added99, round.AddedP99ms)
	}
	m50, m99 := median(added50), median(added99)
	sustainable := 0.0
	for _, step := range r.Steps {
		if step.Sustainable {
			sustainable = step.Proxied.Offered
		}
	}
	ran := func(name string) bool { return slices.Contains(r.Ran, name) }
	b.WriteString("| Measure | Result | Target | Verdict |\n|---|---|---|---|\n")
	if ran("latency") {
		fmt.Fprintf(&b, "| Latency added at %.0f/s, median of %d rounds | p50 %+.2f ms, p99 %+.2f ms | p50 at most 1 ms, p99 at most 5 ms | %s |\n",
			r.Settings.Rate, len(r.Latency), m50, m99, verdict(m50 <= 1 && m99 <= 5))
	}
	if ran("drops") {
		fmt.Fprintf(&b, "| Drops at %.0f/s for %s | %d of %d exchanges, %d errors | None | %s |\n",
			r.Settings.DropRate, r.Settings.DropPhase, r.Drops.Capture.DroppedTotal(), r.Drops.Capture.Observed, r.Drops.Phase.Errors,
			verdict(r.Drops.Capture.DroppedTotal() == 0 && r.Drops.Phase.Errors == 0))
		rss := float64(r.Drops.Capture.PeakRSSBytes) / (1 << 20)
		fmt.Fprintf(&b, "| Capture peak resident set, %.0f/s run | %.0f MiB | At most 300 MiB | %s |\n", r.Settings.DropRate, rss, verdict(rss <= 300))
	}
	if ran("steps") {
		fmt.Fprintf(&b, "| Highest sustainable recording rate | %.0f/s | At least 2,000/s | %s |\n", sustainable, verdict(sustainable >= 2000))
	}
	if ran("replay") {
		fmt.Fprintf(&b, "| Replay rate, %d records | %.0f records/s, %.0f calls/s | At least 300 records/s | %s |\n",
			r.Replay.Records, r.Replay.RecordsPerSecond, r.Replay.CallsPerSecond, verdict(r.Replay.RecordsPerSecond >= 300 && r.Replay.Complete))
	}
	if ran("fairness") {
		fmt.Fprintf(&b, "| Fairness, %d-record session and %d of %d records | last short session done at %.0f%% of the run | Within 30%% | %s |\n",
			r.Fairness.LongRecords, r.Fairness.ShortSessions, r.Fairness.ShortRecords, 100*r.Fairness.LastShortFinishShare, verdict(r.Fairness.LastShortFinishShare <= 0.30))
	}
	b.WriteString("\n")
	b.WriteString("| Phase | Offered/s | Achieved/s | Errors | p50 ms | p90 ms | p99 ms | max ms |\n|---|---|---|---|---|---|---|---|\n")
	row := func(label string, p Phase) {
		fmt.Fprintf(&b, "| %s | %.0f | %.0f | %d | %.2f | %.2f | %.2f | %.2f |\n", label, p.Offered, p.Achieved, p.Errors, p.P50, p.P90, p.P99, p.Max)
	}
	for i, round := range r.Latency {
		row(fmt.Sprintf("Round %d direct", i+1), round.Direct)
		row(fmt.Sprintf("Round %d proxied", i+1), round.Proxied)
	}
	if ran("drops") {
		row("Drops run, proxied", r.Drops.Phase)
	}
	for _, step := range r.Steps {
		row(fmt.Sprintf("Step %.0f/s direct", step.Proxied.Offered), step.Direct)
		row(fmt.Sprintf("Step %.0f/s proxied, %d dropped", step.Proxied.Offered, step.Capture.DroppedTotal()), step.Proxied)
	}
	return b.String()
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := slices.Sorted(slices.Values(values))
	return sorted[len(sorted)/2]
}
