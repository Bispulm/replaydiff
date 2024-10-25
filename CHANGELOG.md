# Changelog

## 0.1.0, unreleased

The first release candidate. See the README for what is tested and what is measured.

### Capture

- Reverse proxy for HTTP/1.1, HTTP/2 and unary gRPC, with bounded memory and a non-blocking
  queue. Live traffic is forwarded even when recording fails, and drops are counted by reason.
- Rule-based redaction before storage: mandatory credential headers, query parameters, JSON
  paths and protobuf fields. Anything that can't be sanitized is omitted, never stored raw.
- Segmented, versioned traffic format with per-record checksums and recovery from damage.

### Replay and comparison

- Replay to allowlisted origins only, with per-session ordering, fair scheduling, rate limits
  and an explicit allowlist for mutating methods and gRPC methods.
- Three-way comparison of JSON and protobuf responses against two baselines, with noise
  explained per field and type, latency and error-rate checks, and uncertain findings where
  the evidence can't support a conclusion.
- A CI gate with three exit codes, a policy with waivers, and JSON, JUnit and Markdown output.

### Deployment and operations

- Helm chart running capture as a sidecar, a distroless image, and a Compose stack.
- Prometheus metrics and health on a separate admin listener, OpenTelemetry traces when
  configured, and a Grafana dashboard. No telemetry carries traffic content.
- Benchmark harness and measured results against targets set beforehand.
