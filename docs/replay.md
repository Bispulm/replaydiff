# Replay

`replaydiff run` sends recorded requests to two baselines and a candidate.

## Destinations

Replay sends only to origins given on the command line, each of which must also
be on the allowlist:

```bash
replaydiff run --traffic ./traffic --report report.json --redact redact.yaml \
  --baseline-a http://a.internal:8080 --baseline-b http://b.internal:8080 \
  --candidate http://c.internal:8080 \
  --allow-origin http://a.internal:8080 \
  --allow-origin http://b.internal:8080 \
  --allow-origin http://c.internal:8080
```

- A target must be a bare origin. A path, query, fragment or credentials in the
  URL are errors.
- A target missing from the allowlist stops the run before any traffic is sent.
- The two baselines and the candidate must be different origins. Comparing a
  service with itself would always look clean.
- Nothing in a record can choose a destination. A record provides only a path and
  query, and the request URL is assembled field by field from the configured origin.
  `Host`, `Forwarded` and `X-Forwarded-*` from the recording are not sent.
- Recorded `traceparent`, `tracestate` and `baggage` are not sent, since they belong to
  the production call the record came from. With tracing on, each call carries replay's
  own trace context instead. See [traces](deployment.md#traces).
- Redirects are never followed. A 3xx response is recorded as the result.
- Proxy environment variables such as `HTTP_PROXY` are ignored.

**DNS.** The allowlist compares host names as text and doesn't pin addresses. If a
listed name resolves somewhere unexpected, traffic goes there. Use names you control
or IP addresses, and don't allowlist anything an untrusted party can change.

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

`--allow-method POST` repeats side effects on all three targets. Use it only against
disposable environments.

## Comparable targets

The tool doesn't make stateful targets equivalent. Baseline A and B must run the same
version, and all three must hold comparable data before the replay starts, or the
differences you see will come from the data rather than the code.

## Scheduling

Records with the same session key form a session. Sessions take turns in a FIFO, and
a session has at most one record in flight. A record is sent to all three targets at
once, and the session's next record starts only after all three finish.

This gives the following guarantees:

- A session's requests reach each target in their original order, and each finishes
  before the next begins.
- A long session gets the same turns as a short one, so it can't starve others.
- A slow session holds one worker at most.
- All three targets see each record at the same time, so latencies are comparable.

Records without a session key run independently. Sessions beyond
`--max-active-sessions` wait until an active session finishes, so a very long session
can delay ones that haven't started. Only a few records are in memory at once: `Scan`
builds an index, and bodies are read when needed.

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

One logical record makes three upstream calls, so `--rps 100` means about 300 calls
per second in total. The report shows both `records_per_second` and
`upstream_calls_per_second`.

**replaydiff doesn't retry.** It makes one attempt per target for each record, because a
retry would change the load and repeat side effects. A timeout is a recorded outcome, and
unrelated records carry on.

The HTTP client can resend by itself in specific cases. Over HTTP/1.1 this is prevented by
not reusing connections, so each call opens a new one, and all three targets pay that cost
equally. The replay rate in the [benchmarks](benchmarks.md) includes it. Over
HTTP/2 it can't be prevented when a server says it didn't process a request, so those
resends are counted and reported. See [resends](architecture.md#resends).

## Credentials

Redacted headers are never sent, and the placeholder is never used as a value. Supply
real credentials per target from environment variables:

```bash
export BASELINE_TOKEN="Bearer ..."
replaydiff run ... --target-credential baseline-a:Authorization=BASELINE_TOKEN
```

Values are never written to the report, which names only the headers each target was
given. Nothing is ever recovered from a recording.

## Sanitizing responses

`--redact` is required, and should usually be the policy used at capture. Responses are
sanitized with it before they're compared, because values from them can appear in the report as
[evidence](diffing.md#evidence-and-limits).

## Exit codes

| Code | `run` |
|---|---|
| 0 | The replay finished with complete evidence, whatever the findings were |
| 2 | Invalid configuration, execution failure, or incomplete evidence |

**`run` doesn't judge findings.** Use [`report`](ci.md) as the CI gate.

Evidence is incomplete when any of these is true:

- The dataset is damaged or incomplete in any way.
- There were no eligible records.
- The run was interrupted.
- A record couldn't be read back.
- Any call to a baseline failed.

A failing candidate doesn't make evidence incomplete, since finding that is the point.
Records that capture dropped are shown as `capture_drops`, and stop a pass at the gate unless
its policy allows them.

## Current limits

- Only unary gRPC is replayed. Protocols are described in [architecture](architecture.md#protocols).
- Request trailers in a recording aren't sent.
- The report's samples include request paths, which redaction doesn't cover. See
  [redaction limits](redaction.md#known-limits).
