package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigAcceptsDocumentedFields(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
routes: ["GET /v1/orders/*", "* /v1/users/**"]
ignore:
  - route: "GET /v1/orders/*"
    paths: ["$.server_time", "$.items[*].updated_at"]
    types: [string]
  - route: "GET /v1/legacy"
    paths: ["$.debug"]
    ignore_structure: true
unordered_arrays:
  - route: "GET /v1/catalog"
    paths: ["$.items"]
compare_headers: [Cache-Control]
evidence: types
noise: {min_observations: 5, margin: 0.3}
latency: {percentiles: [50, 99], min_samples: 10, max_increase_percent: 15, min_increase_ms: 2}
error_rate: {min_requests: 5, max_increase_points: 2.5}
limits: {max_routes: 10, max_fields_per_route: 20, max_findings: 30, max_evidence_bytes: 40}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 2 || len(cfg.Ignore) != 2 || cfg.Noise.MinObservations != 5 || cfg.Latency.MinSamples != 10 || cfg.ErrorRate.MaxIncreasePoints != 2.5 || cfg.Evidence != EvidenceTypes {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestEmptyConfigGetsDefaults(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Noise.MinObservations != 3 || cfg.Noise.Margin != 0.2 {
		t.Fatalf("noise = %+v", cfg.Noise)
	}
	if cfg.Latency.MinSamples != 20 || cfg.Latency.MaxIncreasePercent != 20 || cfg.Latency.MinIncreaseMillis != 5 || len(cfg.Latency.Percentiles) != 3 {
		t.Fatalf("latency = %+v", cfg.Latency)
	}
	if cfg.Evidence != EvidenceValues {
		t.Fatalf("evidence = %q", cfg.Evidence)
	}
}

// A misspelled ignore rule would silently change what fails, so it must stop the run.
func TestParseConfigRejectsInvalidInput(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown key":          `ignores: []`,
		"unknown nested key":   `noise: {min_observation: 3}`,
		"bad route":            `routes: ["/no/method"]`,
		"route with spaces":    `routes: ["GET /a b"]`,
		"double star midway":   `routes: ["GET /**/a"]`,
		"relative route":       `routes: ["GET a/b"]`,
		"ignore without route": `ignore: [{paths: ["$.a"]}]`,
		"ignore without paths": `ignore: [{route: "GET /a"}]`,
		"bad ignore path":      `ignore: [{route: "GET /a", paths: ["a.b"]}]`,
		"bad ignore type":      `ignore: [{route: "GET /a", paths: ["$.a"], types: [date]}]`,
		"bad unordered path":   `unordered_arrays: [{route: "GET /a", paths: ["items"]}]`,
		"bad evidence":         `evidence: everything`,
		"negative observation": `noise: {min_observations: -1}`,
		"margin above one":     `noise: {margin: 1.5}`,
		"negative margin":      `noise: {margin: -0.1}`,
		"percentile zero":      `latency: {percentiles: [0]}`,
		"percentile above 100": `latency: {percentiles: [101]}`,
		"negative samples":     `latency: {min_samples: -1}`,
		"negative increase":    `latency: {max_increase_percent: -1}`,
		"negative points":      `error_rate: {max_increase_points: -1}`,
		"negative limit":       `limits: {max_routes: -1}`,
		"empty header":         `compare_headers: [""]`,
		"two documents":        "evidence: types\n---\nevidence: values\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(doc)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

// NaN compares false with everything, so a range check written with < and > lets it
// through. A latency limit of NaN would then never report a regression.
func TestNonFiniteValuesAreRefused(t *testing.T) {
	for _, doc := range []string{
		`noise: {margin: .nan}`,
		`latency: {max_increase_percent: .nan}`,
		`latency: {max_increase_percent: .inf}`,
		`latency: {min_increase_ms: .nan}`,
		`latency: {percentiles: [.nan]}`,
		`error_rate: {max_increase_points: .nan}`,
		`error_rate: {max_increase_points: .inf}`,
	} {
		if _, err := ParseConfig([]byte(doc)); err == nil {
			t.Errorf("config must be refused: %s", doc)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diff.yaml")
	if err := os.WriteFile(path, []byte(`routes: ["GET /a"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil || len(cfg.Routes) != 1 {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
	if _, err := LoadConfig(path + ".absent"); err == nil {
		t.Fatal("want error")
	}
	empty, err := LoadConfig("")
	if err != nil || empty.Noise.MinObservations != 3 {
		t.Fatalf("empty path must give defaults: %+v, %v", empty, err)
	}
}

func TestRouteClassification(t *testing.T) {
	classifier, err := newRouteClassifier([]string{"GET /v1/orders/*", "POST /v1/orders", "* /v1/files/**"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/v1/orders/abc", "GET /v1/orders/*"},
		{"GET", "/v1/orders/abc/items", "GET /v1/orders/abc/items"},
		{"GET", "/v2/orders/ord-1/items", "GET /v2/orders/*/items"},
		{"POST", "/v1/orders", "POST /v1/orders"},
		{"PUT", "/v1/files/a/b/c", "* /v1/files/**"},
		{"GET", "/v1/files", "* /v1/files/**"},
		// Without a configured pattern, segments holding a digit are treated as IDs.
		{"GET", "/v1/users/usr-1", "GET /v1/users/*"},
		{"GET", "/v1/users/42/posts/9", "GET /v1/users/*/posts/*"},
		{"GET", "/v1/catalog", "GET /v1/catalog"},
		{"GET", "/", "GET /"},
		{"GET", "/a//b/", "GET /a//b/"},
		{"OPTIONS", "*", "OPTIONS *"},
		{"GET", "/items/a%2Fb1", "GET /items/*"},
	} {
		if got := classifier.route(tc.method, tc.path); got != tc.want {
			t.Errorf("route(%s %s) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestRouteCardinalityIsBounded(t *testing.T) {
	classifier, err := newRouteClassifier(nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for i := range 10 {
		seen[classifier.route("GET", fmt.Sprintf("/%s", strings.Repeat("x", i+1)))] = true
	}
	if len(seen) != 4 || !seen[OtherRoutes] {
		t.Fatalf("routes = %v, want 3 plus the overflow route", seen)
	}
	if classifier.overflowed != 7 {
		t.Fatalf("overflowed = %d", classifier.overflowed)
	}
	// A route seen before the limit keeps its name.
	if got := classifier.route("GET", "/x"); got != "GET /x" {
		t.Fatalf("route = %q", got)
	}
}

func TestLongRoutesAreTruncated(t *testing.T) {
	classifier, err := newRouteClassifier(nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := classifier.route("GET", "/"+strings.Repeat("a", 4096)); len(got) > maxRouteBytes+3 {
		t.Fatalf("route length = %d", len(got))
	}
}

func TestPathMatchesRule(t *testing.T) {
	for _, tc := range []struct {
		rule, path string
		want       bool
	}{
		{"$.a", "$.a", true},
		{"$.a", "$.a.b", true},
		{"$.a", "$.a[*].c", true},
		{"$.a", "$.ab", false},
		{"$.a.b", "$.a", false},
		{"$.items[*].x", "$.items[*].x", true},
		{"$", "$.anything", true},
	} {
		if got := pathMatchesRule(tc.rule, tc.path); got != tc.want {
			t.Errorf("pathMatchesRule(%q, %q) = %t", tc.rule, tc.path, got)
		}
	}
}
