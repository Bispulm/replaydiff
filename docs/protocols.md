# Protocols

HTTP/1.1, HTTP/2 and unary gRPC are supported for capture and replay. Streaming gRPC
calls are forwarded but not stored.

## Capture

The two sides of the proxy are independent, so any client protocol can be combined
with any upstream protocol. Tests cover all nine combinations of HTTP/1.1, h2c and
HTTP/2 over TLS, on servers that accept only that protocol.

| Side | Flags | Protocol |
|---|---|---|
| Client | None | HTTP/1.1 |
| Client | `--h2c` | HTTP/1.1, plus HTTP/2 without TLS |
| Client | `--tls-cert`, `--tls-key` | HTTP/1.1 or HTTP/2, negotiated with ALPN |
| Upstream | `http://` | HTTP/1.1 |
| Upstream | `http://` with `--upstream-h2c` | HTTP/2 only, with no fallback |
| Upstream | `https://` | HTTP/1.1 or HTTP/2, negotiated with ALPN |

`--upstream-ca-file` adds trusted certificates for an `https://` upstream.

A record's `protocol` is the one the client used. It doesn't describe the upstream hop.

**h2c is for development.** It is unencrypted and uses prior knowledge only. The
`Upgrade: h2c` handshake isn't supported.

## Replay

| Target | Flags | Protocol |
|---|---|---|
| `http://` | None | HTTP/1.1 |
| `http://` | `--target-h2c` | HTTP/2 only, with no fallback |
| `https://` | None | HTTP/1.1 or HTTP/2, negotiated with ALPN |

`--target-h2c` and `--target-ca-file` apply to all targets. Targets should be reached the
same way, or comparisons would reflect the protocol as well as the code.

Replay uses each target's configured protocol, not the one the record was captured on.
Each result records the protocol its response arrived on, and the report counts them per
target under `protocols`. Check this if you need to confirm a run really used HTTP/2.

## Resends

Replay makes one attempt per target, with no retries of its own. The HTTP client can still
send a request again by itself in these cases:

| Protocol | Case | Handling |
|---|---|---|
| HTTP/1.1 | A reused connection fails, even if the target already acted | Prevented, because connections aren't reused |
| HTTP/2 | The server sends `REFUSED_STREAM` | Can't be disabled. Counted. |
| HTTP/2 | The server sends `GOAWAY` and the stream is above its last-processed ID | Can't be disabled. Counted. |

In the HTTP/2 cases, RFC 9113 means the server has said it didn't process the request, so a
resend shouldn't repeat side effects unless the server is wrong about that. Tests observed
that `PROTOCOL_ERROR`, `INTERNAL_ERROR`, a closed connection and a `GOAWAY` covering the
stream aren't resent, with the Go version in `go.mod`. A newer version could change this,
so the count is the thing to rely on.

Each result's `attempts` is how many times the request was written, and `resends` in the
report totals the extras per target. `run` prints a warning if any occurred.

## gRPC

gRPC needs HTTP/2. Capture needs `--h2c` or TLS for clients and `--upstream-h2c` or an
`https://` upstream. Replay needs `--target-h2c` or `https://` targets.

Messages are read with a compiled descriptor set, not generated code or server reflection.
Build one with `--include_imports`, so that it holds everything the schema refers to:

```bash
protoc --include_imports --descriptor_set_out=orders.binpb orders.proto

replaydiff capture --h2c --upstream http://127.0.0.1:18201 --upstream-h2c \
  --out ./traffic --redact redact.yaml --descriptor-set orders.binpb

replaydiff inspect --traffic ./traffic --descriptor-set orders.binpb

replaydiff run ... --target-h2c --descriptor-set orders.binpb \
  --allow-rpc /fixture.orders.v1.OrderService/GetOrder
```

Each gRPC record stores the digest of the set it was redacted with. `run` skips records made
with a different set, because their messages were redacted and encoded with another schema.
See [ADR 0009](adr/0009-grpc-is-read-with-a-descriptor-set.md) for why.

### Capture

| Call | Result |
|---|---|
| Unary, `application/grpc` or `application/grpc+proto` | Recorded. Request and response bodies each hold one message, decompressed and without its length prefix. |
| Streaming, in either direction | Forwarded. Body omitted as `grpc_streaming`, and not replayable. |
| Another codec, such as `application/grpc+json` | Forwarded. Body omitted as `grpc_unsupported_codec`. |
| No `--descriptor-set`, or a method the set doesn't have | Forwarded. Body omitted as `proto_descriptor_missing` or `proto_method_unknown`. |

[Redaction](redaction.md#protobuf-fields) lists the other cases where a message isn't stored.

HTTP and gRPC status are stored separately, because a failed call normally still has HTTP 200.
The gRPC status comes from the trailers, or from the headers of a trailers-only response.
gzip, deflate and zstd messages are decompressed with the usual size limit.

### Replay

| Record | Result | Counted under |
|---|---|---|
| Method listed in `--allow-rpc` | Replayed | |
| Method not listed | Skipped, even if POST is allowed | `grpc_method_not_allowed` |
| Made with another descriptor set | Skipped | `descriptor_mismatch` |

`--allow-rpc` is checked against the set at startup. A method the set doesn't have, or a
streaming one, is an error. gRPC uses POST for every method, so the method can't say whether
replaying is safe, and only the allowlist can.

Each call is one uncompressed message, so every target receives the same sanitized bytes. It
carries `te: trailers` and a `grpc-timeout` set from `--timeout`, rather than whatever deadline
the original call had left.

Replay sends gRPC with the standard HTTP client, not a gRPC library, so retry and hedging
policies from a service config don't apply. The HTTP/2 resends described below are still
counted.
