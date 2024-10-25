# Deployment

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
| `capture.otlpEndpoint` | | Turns tracing on. See [observability](observability.md). |
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
