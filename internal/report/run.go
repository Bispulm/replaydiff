// Package report reads run results, applies the CI policy, and renders the outcome.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Bispulm/replaydiff/internal/diff"
	"github.com/Bispulm/replaydiff/internal/replay"
)

// Schema identifies the run report format.
const Schema = "replaydiff.run/v1"

// VerdictNotEvaluated marks a run file, which holds evidence and findings but no
// judgment. Only the gate gives a verdict, so a completed run can't be mistaken for a
// passed check.
const VerdictNotEvaluated = "not_evaluated"

// Config records run settings. Credential values are deliberately absent: it names
// only the headers each target was given.
type Config struct {
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

// Run is the file written by the run command and read by the report command.
type Run struct {
	Schema           string                 `json:"schema"`
	Verdict          string                 `json:"verdict"`
	EvidenceComplete bool                   `json:"evidence_complete"`
	Problems         []string               `json:"problems,omitempty"`
	Config           Config                 `json:"config"`
	Summary          *replay.Summary        `json:"summary"`
	Comparison       *diff.Result           `json:"comparison,omitempty"`
	Samples          []*replay.RecordResult `json:"samples,omitempty"`
}

// Write saves a run atomically, so that a crash can't leave a partial file for a later
// step to read as complete. The file is readable only by its owner.
func Write(path string, run *Run) error {
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return writeFile(path, append(data, '\n'))
}

func writeFile(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".replaydiff-report-*")
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	if _, err := temp.Write(data); err != nil {
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

// Load reads a run file strictly. A file this build can't fully understand isn't
// evidence of anything.
func Load(path string) (*Run, error) {
	data, err := os.ReadFile(path) //nolint:gosec // The path is the operator's own argument.
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, errors.New("read report: not a valid report file")
	}
	if probe.Schema != Schema {
		return nil, fmt.Errorf("read report: unsupported schema %q: this build reads %s", probe.Schema, Schema)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var run Run
	if err := dec.Decode(&run); err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("read report: unexpected data after the report")
	}
	return &run, nil
}
