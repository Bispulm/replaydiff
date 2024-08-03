# ADR 0010: Capture deploys as a sidecar, and telemetry carries no traffic

Status: accepted

## Context

Capture has to sit in the request path of a service running in Kubernetes, and operators need
to know whether it is recording, dropping or falling behind. Two constraints shape how. The
brief excludes mutating admission webhooks. And paths aren't redacted, so anything that
copies request details into metrics or traces could carry identifiers or secrets out of the
redaction boundary.

## Decision

- Ship a Helm chart that renders the service and capture in one pod. The Service targets
  capture, which forwards to the service on localhost. No webhook injects anything.
- Give capture an admin listener, apart from the traffic port, for `/metrics`, `/livez` and
  `/readyz`, so probes and scrapes are never recorded. Readiness turns false when shutdown
  begins, and both containers pause before stopping so endpoints go first.
- Expose Prometheus metrics from a private registry. The counters are read from capture's own
  statistics at scrape time, so they agree with what it prints when it stops. Every drop
  reason is exported from zero, so alerts work before the first drop.
- Draw every label and span attribute from constants in the code, plus status codes. Never
  paths, queries, headers, bodies or RPC names, and methods outside the standard set become
  `_OTHER`.
- Export traces over OTLP only when an endpoint is configured, using the standard `OTEL_*`
  variables. Capture reads a client's `traceparent` to join its trace but never changes what
  it forwards. Replay drops recorded trace headers and sends its own per call.
- Give `run` no metrics. It is a batch command whose report is its output.
- Test the deployment on kind with a cluster that has its own kubeconfig, and serialize such
  tests with other heavy workloads through a lock directory.

## Alternatives considered

**A mutating webhook.** Excluded by the brief, and it adds a cluster-wide component with its
own failure modes for something a chart can render.

**Serving metrics on the traffic port.** Scrapes and probes would pass through the proxy and be
recorded, and the service's own paths could collide with them.

**Path or route labels on metrics.** Useful for drill-down, but paths aren't redacted, and
the cardinality would follow the traffic. Per-route detail belongs in the run report, which is
redacted.

**Pushing metrics from `run`.** It would need a Pushgateway and adds little over the report and
traces.

**Forwarding a new traceparent to the service from capture.** It would make capture's span the
service's parent, but capture would no longer be transparent, and the service would see a
header the client didn't send.

## Consequences

- Recordings live in the pod's volume. A claim keeps them past the pod. Several replicas on a
  ReadWriteOnce claim must share a node.
- The duration histogram includes upstream time, so it isn't capture's overhead. That is left to
  the benchmarks.
- A recording dropped because the queue was full has no span. Metrics count it.
- The chart needs Kubernetes 1.30 or later for its `preStop` sleep handler.
