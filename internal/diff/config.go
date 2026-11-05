// Package diff compares a candidate's responses with two baselines.
//
// Baseline disagreement only ever explains differences in values. A field the
// candidate removed or retyped stays a finding however noisy that field is. Severity
// here says what was seen. Whether it fails a build is decided by CI policy.
package diff

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/Bispulm/replaydiff/internal/redact"
)

// OtherRoutes collects traffic once the route limit is reached.
const OtherRoutes = "(other routes)"

// maxRouteBytes bounds a route label.
const maxRouteBytes = 256

// Evidence modes.
const (
	// EvidenceValues puts bounded, sanitized values in findings.
	EvidenceValues = "values"
	// EvidenceTypes puts only JSON types in findings.
	EvidenceTypes = "types"
)

// IgnoreRule permits value differences at paths on a route. Structural changes stay
// detectable unless IgnoreStructure is set.
type IgnoreRule struct {
	Route           string   `yaml:"route" json:"route"`
	Paths           []string `yaml:"paths" json:"paths"`
	Types           []string `yaml:"types" json:"types,omitempty"`
	IgnoreStructure bool     `yaml:"ignore_structure" json:"ignore_structure,omitempty"`
}

// ArrayRule says array order doesn't matter at paths on a route.
type ArrayRule struct {
	Route string   `yaml:"route" json:"route"`
	Paths []string `yaml:"paths" json:"paths"`
}

// NoiseConfig controls noise detection.
type NoiseConfig struct {
	// MinObservations is how many comparisons of a field are needed before
	// baseline disagreement is accepted as noise.
	MinObservations int `yaml:"min_observations" json:"min_observations"`
	// Margin is how far the candidate's difference rate may exceed the baselines'
	// disagreement rate and still be explained by noise.
	Margin float64 `yaml:"margin" json:"margin"`
}

// LatencyConfig controls latency comparison.
type LatencyConfig struct {
	Percentiles        []float64 `yaml:"percentiles" json:"percentiles"`
	MinSamples         int       `yaml:"min_samples" json:"min_samples"`
	MaxIncreasePercent float64   `yaml:"max_increase_percent" json:"max_increase_percent"`
	MinIncreaseMillis  float64   `yaml:"min_increase_ms" json:"min_increase_ms"`
}

// ErrorRateConfig controls error-rate comparison.
type ErrorRateConfig struct {
	MinRequests       int     `yaml:"min_requests" json:"min_requests"`
	MaxIncreasePoints float64 `yaml:"max_increase_points" json:"max_increase_points"`
}

// Limits bounds what a comparison holds and reports.
type Limits struct {
	MaxRoutes         int `yaml:"max_routes" json:"max_routes"`
	MaxFieldsPerRoute int `yaml:"max_fields_per_route" json:"max_fields_per_route"`
	MaxFindings       int `yaml:"max_findings" json:"max_findings"`
	MaxEvidenceBytes  int `yaml:"max_evidence_bytes" json:"max_evidence_bytes"`
}

// Config configures a comparison.
type Config struct {
	Routes          []string        `yaml:"routes" json:"routes,omitempty"`
	Ignore          []IgnoreRule    `yaml:"ignore" json:"ignore,omitempty"`
	UnorderedArrays []ArrayRule     `yaml:"unordered_arrays" json:"unordered_arrays,omitempty"`
	CompareHeaders  []string        `yaml:"compare_headers" json:"compare_headers,omitempty"`
	Evidence        string          `yaml:"evidence" json:"evidence"`
	Noise           NoiseConfig     `yaml:"noise" json:"noise"`
	Latency         LatencyConfig   `yaml:"latency" json:"latency"`
	ErrorRate       ErrorRateConfig `yaml:"error_rate" json:"error_rate"`
	Limits          Limits          `yaml:"limits" json:"limits"`
}

// LoadConfig reads a config file. An empty path gives the defaults.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return ParseConfig(nil)
	}
	data, err := os.ReadFile(path) //nolint:gosec // The path is the operator's own flag.
	if err != nil {
		return nil, fmt.Errorf("read diff config: %w", err)
	}
	return ParseConfig(data)
}

// ParseConfig decodes and validates a config. Unknown keys are errors, because a
// misspelled rule that was ignored would silently change what a run reports.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse diff config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse diff config: expected a single document")
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid diff config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	c.Evidence = cmp.Or(c.Evidence, EvidenceValues)
	c.Noise.MinObservations = cmp.Or(c.Noise.MinObservations, 3)
	c.Noise.Margin = cmp.Or(c.Noise.Margin, 0.2)
	if len(c.Latency.Percentiles) == 0 {
		c.Latency.Percentiles = []float64{50, 95, 99}
	}
	c.Latency.MinSamples = cmp.Or(c.Latency.MinSamples, 20)
	c.Latency.MaxIncreasePercent = cmp.Or(c.Latency.MaxIncreasePercent, 20)
	c.Latency.MinIncreaseMillis = cmp.Or(c.Latency.MinIncreaseMillis, 5)
	c.ErrorRate.MinRequests = cmp.Or(c.ErrorRate.MinRequests, 20)
	c.ErrorRate.MaxIncreasePoints = cmp.Or(c.ErrorRate.MaxIncreasePoints, 1)
	c.Limits.MaxRoutes = cmp.Or(c.Limits.MaxRoutes, 1000)
	c.Limits.MaxFieldsPerRoute = cmp.Or(c.Limits.MaxFieldsPerRoute, 2000)
	c.Limits.MaxFindings = cmp.Or(c.Limits.MaxFindings, 1000)
	c.Limits.MaxEvidenceBytes = cmp.Or(c.Limits.MaxEvidenceBytes, 120)
}

var jsonTypes = map[string]bool{
	"object": true, "array": true, "string": true, "number": true, "boolean": true, "null": true, "text": true,
}

func (c *Config) validate() error {
	for _, route := range c.Routes {
		if _, err := parseRoutePattern(route); err != nil {
			return err
		}
	}
	for _, rule := range c.Ignore {
		if rule.Route == "" || len(rule.Paths) == 0 {
			return errors.New("ignore: a rule needs a route and paths")
		}
		if _, err := parseRoutePattern(rule.Route); err != nil {
			return err
		}
		if err := validateFieldPaths(rule.Paths); err != nil {
			return fmt.Errorf("ignore: %w", err)
		}
		for _, name := range rule.Types {
			if !jsonTypes[name] {
				return fmt.Errorf("ignore: unknown type %q", name)
			}
		}
	}
	for _, rule := range c.UnorderedArrays {
		if rule.Route == "" || len(rule.Paths) == 0 {
			return errors.New("unordered_arrays: a rule needs a route and paths")
		}
		if _, err := parseRoutePattern(rule.Route); err != nil {
			return err
		}
		if err := validateFieldPaths(rule.Paths); err != nil {
			return fmt.Errorf("unordered_arrays: %w", err)
		}
	}
	for _, name := range c.CompareHeaders {
		if strings.TrimSpace(name) == "" {
			return errors.New("compare_headers: empty name")
		}
		// Sanitizing removes these, so they would read as absent on every target and the
		// comparison would silently find nothing.
		if redact.HeaderIsDropped(name) {
			return fmt.Errorf("compare_headers: %q is removed when responses are sanitized, so it can't be compared", name)
		}
	}
	switch c.Evidence {
	case "", EvidenceValues, EvidenceTypes:
	default:
		return fmt.Errorf("evidence: want %q or %q", EvidenceValues, EvidenceTypes)
	}
	switch {
	case c.Noise.MinObservations < 0:
		return errors.New("noise.min_observations must not be negative")
	case c.Noise.Margin < 0 || c.Noise.Margin > 1:
		return errors.New("noise.margin must be between 0 and 1")
	case c.Latency.MinSamples < 0, c.Latency.MaxIncreasePercent < 0, c.Latency.MinIncreaseMillis < 0:
		return errors.New("latency values must not be negative")
	case c.ErrorRate.MinRequests < 0, c.ErrorRate.MaxIncreasePoints < 0:
		return errors.New("error_rate values must not be negative")
	case c.Limits.MaxRoutes < 0, c.Limits.MaxFieldsPerRoute < 0, c.Limits.MaxFindings < 0, c.Limits.MaxEvidenceBytes < 0:
		return errors.New("limits must not be negative")
	}
	for _, percentile := range c.Latency.Percentiles {
		if percentile <= 0 || percentile > 100 {
			return fmt.Errorf("latency.percentiles: %v isn't between 0 and 100", percentile)
		}
	}
	return nil
}

func validateFieldPaths(paths []string) error {
	for _, path := range paths {
		if path != "$" && !strings.HasPrefix(path, "$.") && !strings.HasPrefix(path, "$[") {
			return fmt.Errorf("path %q must start with $", path)
		}
	}
	return nil
}

// pathMatchesRule reports whether a normalized field path is the rule's path or
// inside it.
func pathMatchesRule(rule, path string) bool {
	if !strings.HasPrefix(path, rule) {
		return false
	}
	if len(path) == len(rule) {
		return true
	}
	next := path[len(rule)]
	return next == '.' || next == '['
}

// routePattern matches METHOD /path, where * matches one segment, a trailing ** any
// remainder, and a method of * any method.
type routePattern struct {
	text     string
	method   string
	segments []string
	rest     bool
}

func parseRoutePattern(text string) (*routePattern, error) {
	method, path, ok := strings.Cut(text, " ")
	if !ok || method == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, " ") {
		return nil, fmt.Errorf("route %q must have the form METHOD /path", text)
	}
	pattern := &routePattern{text: text, method: method}
	pattern.segments = strings.Split(path[1:], "/")
	for i, segment := range pattern.segments {
		if segment != "**" {
			continue
		}
		if i != len(pattern.segments)-1 {
			return nil, fmt.Errorf("route %q: ** is only allowed at the end", text)
		}
		pattern.rest = true
		pattern.segments = pattern.segments[:i]
	}
	return pattern, nil
}

func (p *routePattern) matches(method, path string) bool {
	if p.method != "*" && p.method != method {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		return false
	}
	segments := strings.Split(path[1:], "/")
	if p.rest {
		if len(segments) < len(p.segments) {
			return false
		}
		segments = segments[:len(p.segments)]
	} else if len(segments) != len(p.segments) {
		return false
	}
	for i, want := range p.segments {
		if want != "*" && want != segments[i] {
			return false
		}
	}
	return true
}

var (
	digit          = regexp.MustCompile(`[0-9]`)
	versionSegment = regexp.MustCompile(`^v[0-9]+$`)
)

// routeClassifier assigns traffic to named routes, with a bounded number of names so
// that unusual paths can't grow memory or the report without limit.
type routeClassifier struct {
	patterns   []*routePattern
	limit      int
	mu         sync.Mutex
	known      map[string]bool
	overflowed int
}

func newRouteClassifier(patterns []string, limit int) (*routeClassifier, error) {
	classifier := &routeClassifier{limit: limit, known: make(map[string]bool)}
	for _, text := range patterns {
		pattern, err := parseRoutePattern(text)
		if err != nil {
			return nil, err
		}
		classifier.patterns = append(classifier.patterns, pattern)
	}
	return classifier, nil
}

func (r *routeClassifier) route(method, path string) string {
	name := r.name(method, path)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.known[name] {
		return name
	}
	if len(r.known) >= r.limit {
		r.overflowed++
		return OtherRoutes
	}
	r.known[name] = true
	return name
}

func (r *routeClassifier) name(method, path string) string {
	for _, pattern := range r.patterns {
		if pattern.matches(method, path) {
			return pattern.text
		}
	}
	// With no configured pattern, a segment holding a digit is taken to be an ID, unless
	// it looks like an API version. This groups similar requests, which is what gives
	// noise detection repeated observations, and it keeps most identifiers out of reports.
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if digit.MatchString(segment) && !versionSegment.MatchString(segment) {
			segments[i] = "*"
		}
	}
	name := method + " " + strings.Join(segments, "/")
	if len(name) > maxRouteBytes {
		name = name[:maxRouteBytes] + "..."
	}
	return name
}
