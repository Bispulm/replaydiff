package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestTracingIsOffWithoutAnEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	tracing, err := SetupTracing(t.Context(), "replaydiff-test")
	if err != nil {
		t.Fatal(err)
	}
	if tracing.Enabled() {
		t.Fatal("tracing must be off unless an endpoint is configured")
	}
	if err := tracing.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestTracingCanBeTurnedOffExplicitly(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	for name, env := range map[string][2]string{
		"sdk disabled":  {"OTEL_SDK_DISABLED", "true"},
		"exporter none": {"OTEL_TRACES_EXPORTER", "none"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			tracing, err := SetupTracing(t.Context(), "replaydiff-test")
			if err != nil {
				t.Fatal(err)
			}
			if tracing.Enabled() {
				t.Fatal("tracing must be off")
			}
		})
	}
}

// Spans go to the configured OTLP endpoint, and shutting down flushes them.
func TestTracingExportsToTheConfiguredEndpoint(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
	}))
	defer collector.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	tracing, err := SetupTracing(t.Context(), "replaydiff-test")
	if err != nil {
		t.Fatal(err)
	}
	if !tracing.Enabled() {
		t.Fatal("tracing must be on with an endpoint")
	}
	_, span := tracing.Tracer().Start(t.Context(), "test")
	span.End()
	if err := tracing.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) == 0 || paths[0] != "/v1/traces" {
		t.Fatalf("collector saw %v", paths)
	}
}
