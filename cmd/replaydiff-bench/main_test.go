package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The harness runs end to end with tiny workloads. This checks the harness, not the
// numbers, which a quick run can't support.
func TestQuickRunProducesEveryMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs capture")
	}
	bin := filepath.Join(t.TempDir(), "replaydiff")
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "../replaydiff").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"--capture", bin, "--quick", "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(out, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var results Results
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatal(err)
	}
	switch {
	case len(results.Latency) != 1 || results.Latency[0].Proxied.Achieved == 0 || results.Latency[0].Direct.P50 == 0:
		t.Errorf("latency = %+v", results.Latency)
	case results.Drops.Capture.Observed == 0 || results.Drops.Capture.PeakRSSBytes == 0:
		t.Errorf("drops = %+v", results.Drops)
	case len(results.Steps) == 0:
		t.Error("no rate steps")
	case results.Replay.Replayed != 100 || !results.Replay.Complete:
		t.Errorf("replay = %+v", results.Replay)
	case results.Fairness.RunSeconds == 0:
		t.Errorf("fairness = %+v", results.Fairness)
	}
	if !strings.Contains(stdout.String(), "| Replay rate") {
		t.Errorf("summary = %s", stdout.String())
	}
}
