# Deployment and observability

replaydiff runs in Kubernetes as a sidecar: the service and capture share a pod, and the
Service sends traffic to capture, which forwards it to the service on localhost. There is
no mutating webhook. The chart adds the sidecar to a Deployment it renders itself.

## Image

```bash
make image                          # builds replaydiff:dev
make image IMAGE=registry.example/replaydiff:0.1.0 VERSION=0.1.0
```

One image holds `replaydiff`, the entrypoint, and `replaydiff-fixture`. It is a static build
on a distroless base, runs as user 65532, and has no shell. Base images are pinned by digest.

## Helm chart

[`deploy/helm/replaydiff`](../deploy/helm/replaydiff) needs Kubernetes 1.30 or later, for the
`preStop` sleep handler.

```bash
helm install orders deploy/helm/replaydiff \
  --set app.image.repository=registry.example/orders --set app.image.tag=1.4.2 \
  --set app.port=8080 \
  --set-file capture.redactPolicy=redact.yaml
```

It renders:

| Object | Purpose |
|---|---|
| Deployment | The service and capture in each pod |
| Service | Port `service.port` to capture, and the admin port for scrapes |
| ConfigMap | The redaction policy. A change rolls the pods, so recordings follow the new rules. |
| PersistentVolumeClaim | Only with `storage.persistentVolumeClaim.enabled` and no `existingClaim` |
| ServiceMonitor | Only with `serviceMonitor.enabled`, for the Prometheus Operator |

| Value | Default | Meaning |
|---|---|---|
| `app.image.repository`, `app.image.tag` | Required, appVersion | The service's image |
| `app.port` | `8080` | Where the service listens inside the pod. It should listen on 127.0.0.1 or be unreachable otherwise, so traffic can't bypass capture. |
| `app.command`, `app.args`, `app.env` | | Passed to the service's container |
| `capture.port` | `18200` | The traffic port the Service targets |
| `capture.adminPort` | `18209` | `/metrics`, `/livez`, `/readyz` |
| `capture.redactPolicy` | `query_params: [token]` | The policy recordings are redacted with. See [redaction](redaction.md). |
| `capture.h2c`, `capture.upstreamH2C` | `false` | HTTP/2 without TLS from clients and to the service, for gRPC |
| `capture.descriptorSet.configMap` | | A ConfigMap holding the descriptor set, for gRPC |
| `capture.sessionSecret.secretName` | | A Secret holding the session digest key, so sessions correlate across replicas |
| `capture.maxRequestBody`, `maxResponseBody`, `memoryBudget`, `queue` | `1MiB`, `1MiB`, `256MiB`, `1024` | Capture's bounds. See [architecture](architecture.md#capture). |
| `capture.otlpEndpoint` | | Turns tracing on. See [traces](#traces). |
| `storage.persistentVolumeClaim.enabled` | `false` | Keep recordings on a claim instead of an emptyDir, which is lost with the pod |
| `preStopSleepSeconds` | `5` | A pause before shutdown, so endpoints are removed before connections close |
| `terminationGracePeriodSeconds` | `35` | Room for the pause and both of capture's shutdown phases |

A schema refuses a missing service image, and the chart refuses clashing ports.

### gRPC

```bash
kubectl create configmap orders-descriptors --from-file=descriptors.binpb=orders.binpb
helm install orders deploy/helm/replaydiff ... \
  --set capture.h2c=true --set capture.upstreamH2C=true \
  --set capture.descriptorSet.configMap=orders-descriptors
```

With `capture.h2c`, the Service port declares `appProtocol: kubernetes.io/h2c`. See
[protocols](protocols.md#grpc).

### Security

Both containers run as non-root with a read-only root filesystem, no privilege escalation,
all capabilities dropped and the runtime's default seccomp profile. The pod has no service
account token. Recordings are redacted before they reach the volume, but they are still
production-derived data: limit who can read the claim, and review a sample with `inspect`.

### Shutdown

1. The pod is marked for deletion, and Kubernetes starts removing it from the Service's
   endpoints.
2. Both containers pause for `preStopSleepSeconds` while that takes effect, still serving.
3. Capture gets SIGTERM. Its readiness turns false, it stops accepting, waits for live
   requests, then drains recordings and seals its segment, each phase within
   `capture.shutdownTimeout`.

A recording that was never sealed is reported as incomplete when replayed, so give the pod
time to stop rather than killing it.

### Storage

Each pod records into a directory named after itself, under `/var/lib/replaydiff` in the
traffic volume. With more than one replica on a ReadWriteOnce claim, the pods must share a
node. Otherwise use ReadWriteMany, or one claim per replica.

## Observability

**No metric label, span attribute or log line holds traffic content.** Labels and attributes
come from constants in the code, such as drop reasons and protocols, plus status codes. Paths
aren't redacted, so they never appear either. Tests plant values in every location and check
that none reaches a log or an exported span.

### Metrics and health

`capture --admin-listen ADDR`, which the chart sets from `capture.adminPort`, serves these on
a port of their own, so probes and scrapes are never recorded:

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

Go runtime and process metrics are exported too. The duration histogram includes the
upstream's own time, so it isn't the overhead capture adds, which the
[benchmarks](benchmarks.md) measure. `run` has no metrics, because its report is its output.

```promql
# Recordings are being dropped.
sum by (reason) (rate(replaydiff_capture_records_dropped_total[5m])) > 0

# The queue is close to full, so drops are near.
replaydiff_capture_queue_depth / replaydiff_capture_queue_capacity > 0.8
```

[`deploy/grafana/replaydiff-capture.json`](../deploy/grafana/replaydiff-capture.json) is a
Grafana dashboard of these metrics. Import it and choose a Prometheus data source. A test
checks that it queries only metrics that exist, and every one of capture's.

### Traces

Tracing is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is
set. The chart sets the first from `capture.otlpEndpoint`. Spans go over OTLP/HTTP, configured
by the standard OpenTelemetry variables, and any not yet sent are flushed within five seconds
when the process exits.

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

`replaydiff.capture.result` is `recorded` once the record reaches the writer, and otherwise the
reason it was dropped. A recording dropped because the queue was full has no span.

Capture's span joins the client's trace when the request carries a `traceparent`. Capture
still forwards every header unchanged, and doesn't carry a client's `tracestate` into its own
span. Replay doesn't send recorded trace headers. With tracing on, each replayed call carries
its own context, so a target's spans appear under the call that caused them.

### Logs

Capture logs to stderr through `log/slog`, at the level set by `--log-level`. `run` writes its
summary to stdout and its warnings to stderr.

## Compose

[`compose.yaml`](../compose.yaml) runs a local stack on 127.0.0.1:

| Service | Port | Purpose |
|---|---|---|
| `capture` | 18200, admin 18209 | The fixture's traffic port, recorded into the `traffic` volume |
| `baseline-a`, `baseline-b`, `candidate` | 18201, 18202, 18203 | Replay targets. The candidate has the fixture's regressions. |
| `prometheus` | 18205 | Scrapes capture every 5 seconds |
| `grafana` | 18206 | Capture's dashboard, viewable without logging in |

```bash
make compose-up                                  # docker compose up --build --detach
curl http://127.0.0.1:18200/v1/orders/ord-1      # recorded
open http://127.0.0.1:18206                      # the dashboard
docker compose stop capture                      # seals the recording
docker compose run --rm replay                   # replays it against the three targets
make compose-down                                # removes the stack and its volume
```

Every container except Prometheus and Grafana runs with a read-only filesystem, no new
privileges and no capabilities.

## Replaying inside the cluster

The image has no shell, so the simplest way to replay is a Job that mounts the claim once
the capture pods have stopped. [`test/kind/testdata/replay-job.yaml`](../test/kind/testdata/replay-job.yaml)
is a working example. It runs `inspect`, then `run` against three target Services, then the
`report` gate, whose exit code becomes the Job's result.

## Testing on kind

```bash
make kind-test          # creates replaydiff-dev, runs, deletes it
make kind-test KEEP=1   # keeps the cluster for the next run
```

It builds the image and loads it into a cluster named `replaydiff-dev`, which has its own
kubeconfig file, so your current kubectl context isn't changed. It then installs the chart
with the fixture behind capture, sends traffic through the Service with a credential in the
query and headers, and checks the metrics. Finally it stops the pod and replays from a Job
against two baselines and a candidate. The gate must find the candidate's regressions, and
the credential must appear in no recording or output. Set `REPLAYDIFF_K8S_LOCK` to a
directory path to wait for other heavy workloads on a shared machine.
