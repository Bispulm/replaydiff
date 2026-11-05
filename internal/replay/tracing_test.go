package replay

import (
	"encoding/json"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

const recordedTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func withTraceHeaders(path string) spec {
	return spec{path: path, headers: map[string][]string{
		"Traceparent": {recordedTraceparent},
		"Tracestate":  {"vendor=recorded"},
		"Baggage":     {"user=recorded"},
	}}
}

// A recorded trace context belongs to the production call it was captured from. Sent
// again, it would add three replayed calls to that trace.
func TestRecordedTraceContextIsNotReplayed(t *testing.T) {
	c := newCluster(t, nil)
	mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, []spec{withTraceHeaders("/x")})))
	for _, target := range []*fakeTarget{c.a, c.b, c.c} {
		header := target.seen()[0].Header
		for _, name := range []string{"Traceparent", "Tracestate", "Baggage"} {
			if got := header.Get(name); got != "" {
				t.Errorf("%s sent %q", name, got)
			}
		}
	}
}

// Each call carries replay's own trace context, so a target's spans join the replay's
// trace under the call that caused them.
func TestReplayTracesRunsRecordsAndCalls(t *testing.T) {
	secret := "rdsentinel-replay-trace"
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
	c := newCluster(t, nil)
	cfg := c.config()
	cfg.Tracer = provider.Tracer("test")
	record := withTraceHeaders("/orders/" + secret)
	record.query = "token=" + secret
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{record, {path: "/y"}})))

	spans := exporter.GetSpans()
	byName := map[string][]tracetest.SpanStub{}
	for _, span := range spans {
		byName[span.Name] = append(byName[span.Name], span)
	}
	runs, records, calls := byName["replaydiff run"], byName["replaydiff replay record"], byName["replaydiff replay call"]
	if len(runs) != 1 || len(records) != 2 || len(calls) != 6 {
		t.Fatalf("spans: %d runs, %d records, %d calls", len(runs), len(records), len(calls))
	}
	runID := runs[0].SpanContext.SpanID()
	recordIDs := map[trace.SpanID]bool{}
	for _, span := range records {
		if span.Parent.SpanID() != runID {
			t.Errorf("record span parent %s, want the run", span.Parent.SpanID())
		}
		recordIDs[span.SpanContext.SpanID()] = true
	}
	callIDs := map[string]bool{}
	for _, span := range calls {
		if !recordIDs[span.Parent.SpanID()] {
			t.Errorf("call span parent %s isn't a record span", span.Parent.SpanID())
		}
		callIDs[span.SpanContext.SpanID().String()] = true
		role := ""
		for _, kv := range span.Attributes {
			if kv.Key == attribute.Key("replaydiff.role") {
				role = kv.Value.AsString()
			}
		}
		if role == "" {
			t.Errorf("call span has no role: %v", span.Attributes)
		}
	}

	traceID := runs[0].SpanContext.TraceID().String()
	for _, target := range []*fakeTarget{c.a, c.b, c.c} {
		for _, request := range target.seen() {
			parts := strings.Split(request.Header.Get("Traceparent"), "-")
			if len(parts) != 4 || parts[1] != traceID || !callIDs[parts[2]] {
				t.Errorf("target got traceparent %q, want one under a call span of trace %s", request.Header.Get("Traceparent"), traceID)
			}
		}
	}
	data, err := json.Marshal(spans)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("a span holds traffic content: %s", data)
	}
}
