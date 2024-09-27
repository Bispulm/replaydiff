# ADR 0001: Capture with a reverse proxy

Status: accepted

## Context

Capture has to see complete HTTP/1.1, HTTP/2 and unary gRPC exchanges, redact
them before storage, and run as a Kubernetes sidecar. Packet capture needs
elevated privileges and can't read TLS traffic it doesn't terminate. eBPF adds
kernel requirements.

## Decision

Capture runs as a reverse proxy in front of the service, built on
`net/http/httputil.ReverseProxy`.

## Consequences

- No kernel access or extra privileges are needed, and it works in a sidecar.
- HTTP semantics such as hop-by-hop headers, trailers, flushing and cancellation
  come from a well-tested implementation rather than custom code.
- The proxy is in the request path, so a capture bug or crash affects live
  traffic. Passive capture wouldn't have this risk. Forwarding and recording are
  separated to limit it, and the added latency must be measured and published.
- Only traffic sent through the proxy is captured.
