package telemetry

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Tracing is a process's trace pipeline. When it's off, Tracer returns nil, which the
// capture and replay packages take to mean no spans at all.
type Tracing struct {
	provider *sdktrace.TracerProvider
	service  string
}

// SetupTracing exports spans over OTLP/HTTP when OTEL_EXPORTER_OTLP_ENDPOINT or
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is set, and is off otherwise. The rest comes from
// the standard OTEL_* variables, such as OTEL_TRACES_SAMPLER and
// OTEL_EXPORTER_OTLP_HEADERS. OTEL_SDK_DISABLED=true or OTEL_TRACES_EXPORTER=none turn
// it off explicitly.
func SetupTracing(ctx context.Context, service string) (*Tracing, error) {
	if !tracingConfigured() {
		return &Tracing{service: service}, nil
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("tracing: %w", err)
	}
	attrs := []attribute.KeyValue{attribute.String("service.name", service)}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		attrs = append(attrs, attribute.String("service.version", info.Main.Version))
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewSchemaless(attrs...)),
	)
	return &Tracing{provider: provider, service: service}, nil
}

func tracingConfigured() bool {
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") || strings.EqualFold(os.Getenv("OTEL_TRACES_EXPORTER"), "none") {
		return false
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// Enabled reports whether spans are exported.
func (t *Tracing) Enabled() bool { return t.provider != nil }

// Tracer returns the process's tracer, or nil when tracing is off.
func (t *Tracing) Tracer() trace.Tracer {
	if t.provider == nil {
		return nil
	}
	return t.provider.Tracer("github.com/Bispulm/replaydiff/" + t.service)
}

// Shutdown flushes spans not yet exported, within ctx's deadline.
func (t *Tracing) Shutdown(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}
	if err := t.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	return nil
}
