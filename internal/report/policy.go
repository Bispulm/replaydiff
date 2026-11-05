package report

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Bispulm/replaydiff/internal/diff"
)

// EvidencePolicy says how much evidence a pass needs. Its defaults are strict: anything
// uncertain, and any dropped recording, stops a run from passing until allowed.
type EvidencePolicy struct {
	// MinCompared is how many records must have been compared.
	MinCompared int `yaml:"min_compared" json:"min_compared"`
	// MaxUncertain is how many uncertain findings a pass may have.
	MaxUncertain int `yaml:"max_uncertain" json:"max_uncertain"`
	// AllowUncertain lists uncertain kinds that aren't counted against MaxUncertain.
	AllowUncertain []string `yaml:"allow_uncertain" json:"allow_uncertain,omitempty"`
	// MaxCaptureDropPercent limits recordings capture dropped, out of all it saw.
	MaxCaptureDropPercent float64 `yaml:"max_capture_drop_percent" json:"max_capture_drop_percent"`
	// MaxSkippedPercent limits records replay skipped, out of all readable ones. Skipping
	// is normal, because mutating requests are skipped by default, so the default is 100.
	MaxSkippedPercent float64 `yaml:"max_skipped_percent" json:"max_skipped_percent"`
}

// Waiver excuses findings that are known and accepted. It stays visible in reports with
// its reason, and it can't excuse missing evidence.
type Waiver struct {
	Route string   `yaml:"route" json:"route"`
	Kinds []string `yaml:"kinds" json:"kinds"`
	// Paths narrows the waiver. Without it, the waiver covers the route and kinds.
	Paths  []string `yaml:"paths" json:"paths,omitempty"`
	Reason string   `yaml:"reason" json:"reason"`
}

// Policy decides what a run's findings mean for a build.
type Policy struct {
	// FailOn lists severities and kinds that are regressions. Its default is breaking.
	FailOn   []string       `yaml:"fail_on" json:"fail_on"`
	Evidence EvidencePolicy `yaml:"evidence" json:"evidence"`
	Waivers  []Waiver       `yaml:"waivers" json:"waivers,omitempty"`
}

// LoadPolicy reads a policy file. An empty path gives the defaults.
func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		return ParsePolicy(nil)
	}
	data, err := os.ReadFile(path) //nolint:gosec // The path is the operator's own flag.
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return ParsePolicy(data)
}

// ParsePolicy decodes and validates a policy. Unknown keys are errors, because a
// misspelled rule that was ignored would change what fails a build.
func ParsePolicy(data []byte) (*Policy, error) {
	policy := Policy{Evidence: EvidencePolicy{MinCompared: 1, MaxSkippedPercent: 100}}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse policy: expected a single document")
	}
	if len(policy.FailOn) == 0 {
		policy.FailOn = []string{string(diff.SeverityBreaking)}
	}
	if err := policy.validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &policy, nil
}

// SetFailOn replaces FailOn from a comma-separated list.
func (p *Policy) SetFailOn(list string) error {
	var entries []string
	for _, entry := range strings.Split(list, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	if len(entries) == 0 {
		return errors.New("--fail-on needs at least one severity or kind")
	}
	for _, entry := range entries {
		if !validFailOn(entry) {
			return fmt.Errorf("--fail-on: unknown severity or kind %q", entry)
		}
	}
	p.FailOn = entries
	return nil
}

func validFailOn(entry string) bool {
	switch diff.Severity(entry) {
	case diff.SeverityBreaking, diff.SeverityWarning, diff.SeverityUncertain, diff.SeverityInfo:
		return true
	}
	_, known := diff.SeverityOf(diff.Kind(entry))
	return known
}

func (p *Policy) validate() error {
	for _, entry := range p.FailOn {
		if !validFailOn(entry) {
			return fmt.Errorf("fail_on: unknown severity or kind %q", entry)
		}
	}
	e := p.Evidence
	switch {
	case e.MinCompared < 0, e.MaxUncertain < 0:
		return errors.New("evidence: values must not be negative")
	case e.MaxCaptureDropPercent < 0 || e.MaxCaptureDropPercent > 100:
		return errors.New("evidence.max_capture_drop_percent must be between 0 and 100")
	case e.MaxSkippedPercent < 0 || e.MaxSkippedPercent > 100:
		return errors.New("evidence.max_skipped_percent must be between 0 and 100")
	}
	for _, kind := range e.AllowUncertain {
		if severity, known := diff.SeverityOf(diff.Kind(kind)); !known || severity != diff.SeverityUncertain {
			return fmt.Errorf("evidence.allow_uncertain: %q isn't an uncertain kind", kind)
		}
	}
	for _, waiver := range p.Waivers {
		if waiver.Route == "" || len(waiver.Kinds) == 0 {
			return errors.New("waivers: a waiver needs a route and kinds")
		}
		// A waiver changes what fails a build, so whoever adds one has to say why.
		if strings.TrimSpace(waiver.Reason) == "" {
			return fmt.Errorf("waivers: the waiver for %q needs a reason", waiver.Route)
		}
		for _, kind := range waiver.Kinds {
			if _, known := diff.SeverityOf(diff.Kind(kind)); !known {
				return fmt.Errorf("waivers: unknown kind %q", kind)
			}
		}
	}
	return nil
}

func (p *Policy) minCompared() int { return cmp.Or(p.Evidence.MinCompared, 1) }
