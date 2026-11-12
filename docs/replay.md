# Replay

`replaydiff run` sends recorded requests to two baselines and a candidate.

## Destinations

Replay sends only to origins given on the command line, and each must also be on the
allowlist:

```bash
replaydiff run --traffic ./traffic --report report.json --redact redact.yaml \
  --baseline-a http://a.internal:8080 --baseline-b http://b.internal:8080 \
  --candidate http://c.internal:8080 \
  --allow-origin http://a.internal:8080 \
  --allow-origin http://b.internal:8080 \
  --allow-origin http://c.internal:8080
```

- A target must be a bare origin. A path, query, fragment or credentials in the URL are
  errors.
- A target missing from the allowlist stops the run before any traffic is sent.
- The baselines and the candidate must be different origins, since a service compared with
  itself always looks clean.
- Nothing in a record can choose a destination. The request URL is built from the configured
  origin plus the record's path and query, and recorded `Host`, `Forwarded` and
  `X-Forwarded-*` headers aren't sent.
- Recorded `traceparent`, `tracestate` and `baggage` aren't sent either, since they belong to
  the production call. See [traces](deployment.md#traces).
- Redirects are never followed, so a 3xx is the result. Proxy environment variables such as
  `HTTP_PROXY` are ignored.

**DNS.** The allowlist compares host names as text and doesn't pin addresses, so a listed
name that resolves somewhere unexpected sends traffic there. Use names you control or IP
addresses.

## Eligibility

Having been captured doesn't make a request safe to replay.

| Record | Result | Counted under |
|---|---|---|
| GET, HEAD, OPTIONS | Replayed | |
| Any other method | Skipped unless listed in `--allow-method` | `mutating_method` |
| CONNECT, TRACE | Can't be allowed | |
| Capture marked it unreplayable | Skipped | The reason capture recorded |
| Claims to be eligible but has no stored body | Skipped | `request_body_unavailable` |
| gRPC method not listed in `--allow-rpc` | Skipped, even if POST is allowed | `grpc_method_not_allowed` |
| gRPC, recorded with another descriptor set | Skipped | `descriptor_mismatch` |
| Not gRPC, but with a gRPC `Content-Type` or more than one `Content-Type` | Not sent, as an `invalid_request`, which makes evidence incomplete | |

`--allow-method POST` repeats side effects on all three targets, so use it only against
disposable environments.

## Comparable targets

Baselines A and B must run the same version, and all three targets must hold comparable data
before the replay starts. Otherwise the differences come from the data rather than the code.
replaydiff doesn't make stateful targets equivalent.

## Scheduling

Records with the same session key form a session. Sessions take turns, and each has at most
one record in flight. A record goes to all three targets at once, and the session's next
record starts only after all three finish. So a session's requests reach each target in their
original order, a long session can't starve short ones, a slow session holds at most one
worker, and latencies are comparable because the targets see each record at the same time.

Records without a session key run independently. Sessions beyond `--max-active-sessions` wait
for an active one to finish, so a very long session can delay ones that haven't started.
Bodies are read from disk when needed, so only a few records are in memory at once.

## Rates and limits

| Flag | Limits | Default |
|---|---|---|
| `--rps` | **Logical records** started per second | 50 |
| `--target-rps` | Calls per second to each target | No limit |
| `--concurrency` | In-flight calls across all targets | 32 |
| `--per-target-concurrency` | In-flight calls to each target | 16 |
| `--max-active-sessions` | Sessions worked on at once | 256 |
| `--timeout` | One call, including reading its response | 10s |
| `--max-response-body` | A held response, after decompression | 8 MiB |

One logical record makes three upstream calls, so `--rps 100` means about 300 calls per
second. The report shows both `records_per_second` and `upstream_calls_per_second`.

**replaydiff doesn't retry.** A retry would change the load and repeat side effects, so it
makes one attempt per target, and a timeout is a recorded outcome. The HTTP client can still
resend by itself in a few cases. Over HTTP/1.1, replay prevents that by not reusing
connections, a cost all three targets pay equally and that the replay rate in the
[benchmarks](benchmarks.md) includes. Over HTTP/2 it can't be prevented when a server says it
didn't process a request, so those resends are counted. See [resends](architecture.md#resends).

## Credentials

Redacted headers are never sent, and the placeholder is never used as a value. Supply real
credentials per target from environment variables:

```bash
export BASELINE_TOKEN="Bearer ..."
replaydiff run ... --target-credential baseline-a:Authorization=BASELINE_TOKEN
```

The report names only which headers each target was given, never their values, and nothing is
ever recovered from a recording.

## Sanitizing responses

`--redact` is required, and is usually the policy used at capture. Responses are sanitized
with it before they're compared, because their values can appear in the report as
[evidence](diffing.md#evidence-and-limits).

## Exit codes

`run` exits 0 when the replay finished with complete evidence, whatever it found, and 2 for
invalid configuration, a failure, or incomplete evidence. **It doesn't judge findings.**
[`report`](ci.md) is the CI gate.

Evidence is incomplete if the dataset is damaged or incomplete, no record was eligible, the
run was interrupted, a record couldn't be read back, or a baseline call failed. A failing
candidate doesn't count, since finding that is the point. Records that capture dropped are
shown as `capture_drops`, and stop a pass at the gate unless its policy allows them.

## Current limits

- Only unary gRPC is replayed. Protocols are described in [architecture](architecture.md#protocols).
- Request trailers in a recording aren't sent.
- The report's samples include request paths, which redaction doesn't cover. See
  [redaction limits](redaction.md#known-limits).
