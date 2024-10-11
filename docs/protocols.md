# Protocols

HTTP/1.1 and HTTP/2 are supported for capture and replay. Unary gRPC is planned, and
until then gRPC bodies are omitted and those records aren't replayed.

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
