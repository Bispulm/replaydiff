# Observability

Capture exposes metrics and health on a listener of its own, and capture and `run` can
export traces. **No metric label or span attribute holds traffic content.** Labels and
attributes are drawn from constants in the code, such as drop reasons and protocols, plus
status codes. Paths, queries, headers and bodies never appear, because paths aren't
redacted.

## Metrics and health

`capture --admin-listen ADDR` serves these, apart from the traffic port, so probes and
scrapes are never recorded:

| Path | Purpose |
|---|---|
| `/metrics` | Prometheus metrics |
| `/livez` | 200 while the process runs |
| `/readyz` | 200 while the proxy accepts traffic. It turns 503 as shutdown begins, so a load balancer stops sending first. |

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `replaydiff_capture_exchanges_total` | Counter | | Exchanges the proxy forwarded |
| `replaydiff_capture_records_persisted_total` | Counter | | Records written to storage |
| `replaydiff_capture_records_dropped_total` | Counter | `reason` | Recordings dropped. Every reason is exported from zero. |
| `replaydiff_capture_bodies_omitted_total` | Counter | `reason` | Bodies observed but not stored |
| `replaydiff_capture_storage_sync_failures_total` | Counter | | Failed flushes to disk |
| `replaydiff_capture_queue_depth` | Gauge | | Exchanges waiting to be recorded |
| `replaydiff_capture_queue_capacity` | Gauge | | Queue size, beyond which recordings are dropped |
| `replaydiff_capture_memory_budget_used_bytes` | Gauge | | Body bytes held |
| `replaydiff_capture_memory_budget_bytes` | Gauge | | Body bytes allowed before bodies are omitted |
| `replaydiff_capture_exchange_duration_seconds` | Histogram | `protocol` | From a request arriving to its response finishing, upstream time included |

Go runtime and process metrics (`go_*`, `process_*`) are exported too.

The counters are read from the same statistics capture prints when it stops, so the two
agree. The duration histogram includes the upstream's own time, so it isn't the overhead
capture adds. That is measured separately by the benchmarks.

Useful alerts:

```promql
# Recordings are being dropped.
sum by (reason) (rate(replaydiff_capture_records_dropped_total[5m])) > 0

# The queue is close to full, so drops are near.
replaydiff_capture_queue_depth / replaydiff_capture_queue_capacity > 0.8
```

`run` has no metrics. It is a batch command, and its report is its output.

## Dashboard

[`deploy/grafana/replaydiff-capture.json`](../deploy/grafana/replaydiff-capture.json) shows
exchanges and the share recorded, drops and omitted bodies by reason, queue and memory
budget use, exchange duration by protocol, flush failures and the process's own load. Import
it into Grafana and choose a Prometheus data source. A test checks that every metric it
queries exists and that each of capture's metrics is on it.

## Traces

Tracing is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
is set. Spans are sent over OTLP/HTTP, configured by the standard OpenTelemetry variables,
such as `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` and `OTEL_EXPORTER_OTLP_HEADERS`.
`OTEL_SDK_DISABLED=true` or `OTEL_TRACES_EXPORTER=none` turn it off. Spans not yet sent are
flushed when the process exits, within five seconds.

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 OTEL_TRACES_SAMPLER=parentbased_traceidratio \
OTEL_TRACES_SAMPLER_ARG=0.1 replaydiff capture ...
```

| Span | From | Attributes |
|---|---|---|
| `replaydiff capture` | capture, one per exchange its workers handle | `http.request.method`, `http.response.status_code`, `replaydiff.protocol`, `replaydiff.transport`, `replaydiff.capture.result` |
| `replaydiff run` | `run` | `replaydiff.records`, `replaydiff.replayed`, `replaydiff.complete` |
| `replaydiff replay record` | `run`, one per record | `replaydiff.record.id`, `http.request.method`, `replaydiff.protocol` |
| `replaydiff replay call` | `run`, one per target call | `replaydiff.role`, `replaydiff.outcome`, `replaydiff.attempts`, `http.response.status_code`, `rpc.grpc.status_code` |

A method outside HTTP's standard set is recorded as `_OTHER`. `replaydiff.capture.result` is
`recorded` when the record reached the writer, or the reason it was dropped. Write failures
after that point are counted in metrics. A recording dropped because the queue was full has
no span.

**Trace context.** Capture's span joins the client's trace when the request carries a
`traceparent`, but capture never changes what it forwards, that header included. Replay
doesn't send recorded `traceparent`, `tracestate` or `baggage`, since they belong to the
production call. With tracing on, each replayed call carries its own context, so a target's
spans appear under the call that caused them.

An end-to-end test runs capture and `run` against a stand-in collector, with a secret in the
path, query, a header and the body, and finds it in no exported span.

## Logs

Capture logs to stderr through `log/slog`, at the level set by `--log-level`. Logs never hold
traffic content, including at debug level, which tests check by planting values in every
location. `run` writes its summary to stdout and its warnings to stderr.
