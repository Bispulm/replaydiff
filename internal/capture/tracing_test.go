package capture

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

func tracedHarness(t *testing.T, upstream http.Handler) (*harness, *tracetest.InMemoryExporter) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
	h := newHarness(t, upstream, func(cfg *Config) { cfg.Tracer = provider.Tracer("test") })
	return h, exporter
}

func attributes(span tracetest.SpanStub) map[attribute.Key]attribute.Value {
	out := make(map[attribute.Key]attribute.Value)
	for _, kv := range span.Attributes {
		out[kv.Key] = kv.Value
	}
	return out
}

const (
	clientTraceID  = "4bf92f3577b34da6a3ce929d0e0e4736"
	clientSpanID   = "00f067aa0ba902b7"
	clientTraceCtx = "00-" + clientTraceID + "-" + clientSpanID + "-01"
)

// Capture's span joins the client's trace, but what capture forwards is unchanged: the
// upstream sees the client's own traceparent. No span holds traffic content.
func TestCaptureTracesEachExchangeWithoutChangingIt(t *testing.T) {
	secret := sentinel(t)
	var forwarded string
	h, exporter := tracedHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("Traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	h.send(http.MethodGet, "/orders/"+secret+"?token="+secret, nil, map[string]string{"Traceparent": clientTraceCtx, "X-Note": secret})
	h.close()
	if forwarded != clientTraceCtx {
		t.Fatalf("upstream saw traceparent %q", forwarded)
	}
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("%d spans", len(spans))
	}
	span := spans[0]
	if span.SpanContext.TraceID().String() != clientTraceID || span.Parent.SpanID().String() != clientSpanID {
		t.Fatalf("span isn't in the client's trace: %s, parent %s", span.SpanContext.TraceID(), span.Parent.SpanID())
	}
	attrs := attributes(span)
	if attrs["http.request.method"].AsString() != "GET" || attrs["http.response.status_code"].AsInt64() != 200 ||
		attrs["replaydiff.capture.result"].AsString() != "recorded" || attrs["replaydiff.protocol"].AsString() != "http/1.1" {
		t.Fatalf("attributes = %v", span.Attributes)
	}
	data, err := json.Marshal(spans)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("a span holds traffic content: %s", data)
	}
}

func TestCaptureSpansShowWhyARecordingWasDropped(t *testing.T) {
	h, exporter := tracedHarness(t, jsonHandler(`{}`))
	h.capture.sanitize = func(*exchange) *traffic.Record { panic("broken") }
	h.send(http.MethodPost, "/", []byte(`{}`), map[string]string{"Content-Type": "application/json"})
	h.close()
	spans := exporter.GetSpans()
	if len(spans) != 1 || attributes(spans[0])["replaydiff.capture.result"].AsString() != string(DropSanitizeFailure) {
		t.Fatalf("spans = %+v", spans)
	}
}

// An unusual method is an unbounded value, so spans name it _OTHER.
func TestCaptureSpansDontNameUnusualMethods(t *testing.T) {
	h, exporter := tracedHarness(t, jsonHandler(`{}`))
	h.send("PROPFIND", "/", nil, nil)
	h.close()
	spans := exporter.GetSpans()
	if len(spans) != 1 || attributes(spans[0])["http.request.method"].AsString() != "_OTHER" {
		t.Fatalf("spans = %+v", spans)
	}
}
