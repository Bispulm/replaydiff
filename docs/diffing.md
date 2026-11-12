# Comparison

`replaydiff run` compares each record's responses from baseline A, baseline B and the
candidate, and puts the results in the report's `comparison` section. **Severity isn't CI
policy.** A finding says what was seen, and the [CI gate](ci.md) decides whether it fails a
build.

## What is compared

Responses are sanitized with the redaction policy first, so evidence can't hold values the
policy covers. A redacted field's presence is compared, but not its value or type, since all
three targets show the same placeholder.

For each record, in this order:

1. **The call.** A failed baseline call leaves the record uncompared and the run's evidence
   incomplete. A failed candidate call is a finding.
2. **Status.** A changed class stops the comparison of that record, since the bodies are no
   longer the same kind of response. For gRPC, the [gRPC status](#grpc-status) is compared
   next.
3. **Media type**, ignoring parameters such as `charset`.
4. **Headers** listed in `compare_headers`. Others vary by nature, so they aren't compared.
   Headers that sanitizing removes, such as `ETag` and `Content-Length`, are refused in the
   config.
5. **The body.**

## Bodies

JSON bodies are compared by structure. Form-encoded bodies, and types listed in
`opaque_content_types`, are compared as a whole. Anything else is reported as not comparable.

| Rule | Example | Result |
|---|---|---|
| Object key order doesn't matter | `{"a":1,"b":2}`, `{"b":2,"a":1}` | Equal |
| Numbers keep their precision | `12345678901234567890`, `12345678901234567891` | Different |
| Same number, written differently | `1.0`, `1` | Equal, reported as info |
| Missing isn't null | `{"a":null}`, `{}` | Field removed |
| Types are never coerced | `1`, `"1"` | Type changed |
| Array order matters, unless a rule says otherwise | `[1,2]`, `[2,1]` | Different |

Numbers are compared exactly, except that those with an exponent above 1000 or more than 512
characters are compared as text, to keep comparison cheap. Array elements are compared by
position up to the shorter length, and a different length is its own finding. Anything nested
deeper than 64 levels is compared as a single value.

## Protobuf

gRPC responses are decoded with the run's `--descriptor-set` after redaction, and compared
field by field under protobuf's own rules for presence. Paths use the schema's field names,
such as `$.customer.tier`.

| Field | Rule | Example | Result |
|---|---|---|---|
| A message, `optional` field or `oneof` member | Present only when set | `shipment` unset | Breaking `field_removed` |
| `oneof` | Each member is a field of its own | `card_last4` replaced by `invoice_id` | `field_removed` and `field_added` |
| Any other scalar | Always present, holding its default when unset, because the wire format can't tell those apart | `tier: "gold"` unset | Warning `value_changed` |
| Map | Entries are data, not fields, so keys become `[*]` in paths | Entry removed, added, changed | Warning `map_entry_removed`, info `map_entry_added`, warning `value_changed` at `$.labels[*]` |
| `Any` of a type in the set | Unpacked and compared by field, at most 8 deep. Its packed type is its type, and an `Any` it packs is under `value`. | Another packed type | Breaking `type_changed` |
| `Any` of another type | By a digest of its bytes, which are never shown | | `value_changed` at `.value` |
| A field the set doesn't describe | By presence and wire type only, at a path such as `$['#99']` | | |

Repeated fields compare like JSON arrays, enums by number so that an unknown number still
compares, 64-bit integers exactly, and `bytes` by value, shown as base64.

A candidate message that can't be decoded is breaking `body_invalid`. If the baselines'
messages can't be decoded either, or no descriptor set was given, the record is uncertain
`body_not_compared`. An OK reply must carry a message, so one without is breaking
`body_removed`.

### gRPC status

| Baselines | Candidate | Finding |
|---|---|---|
| OK | Any error | Breaking `grpc_error_introduced` |
| An error that isn't a server fault, such as `not_found` | A server fault | Breaking `grpc_error_introduced` |
| Any | Any other new status | Warning `grpc_status_changed` |
| Disagree | | Uncertain `baseline_status_unstable`, and `grpc_error_introduced` if the candidate's status is a server fault neither had |

Server faults are `unknown`, `deadline_exceeded`, `resource_exhausted`, `unimplemented`,
`internal`, `unavailable`, `data_loss`, any code this build doesn't know, and a call that
ended with no status. Messages are compared only when all three calls returned OK, because a
client discards any message that comes with an error.

## Severity

| Severity | Meaning | Kinds |
|---|---|---|
| Breaking | The contract changed | `status_class_changed`, `grpc_error_introduced`, `field_removed`, `type_changed`, `candidate_call_failed`, `body_removed`, `body_invalid`, `body_type_changed` |
| Warning | Behavior changed, possibly on purpose | `value_changed`, `value_changed_beyond_noise`, `array_length_changed`, `map_entry_removed`, `status_changed`, `grpc_status_changed`, `content_type_changed`, `latency_regression`, `error_rate_regression` |
| Uncertain | The evidence can't support a conclusion. **This isn't a pass.** | `insufficient_baseline_evidence`, `baseline_presence_unstable`, `baseline_type_unstable`, `baseline_status_unstable`, `baseline_content_type_unstable`, `baseline_body_unstable`, `body_not_compared`, `field_limit_reached`, `route_limit_reached` |
| Info | A permitted difference, or noise that was explained | `field_added`, `map_entry_added`, `body_added`, `number_format_changed`, `noise_explained` |

## Noise

Baselines A and B run the same code, so a field that differs between them varies for reasons
other than the code, such as a timestamp or a generated ID. **Noise only ever explains
differences in values.** Structure is checked first and separately, so a field the candidate
removed or retyped is breaking however much its value varies.

Each field is tracked per route and per JSON type, so noise on one route doesn't excuse a
change on another, and disagreement about a field's strings says nothing about a change to
its numbers. The decision compares two rates: how often A and B disagreed, and how often the
candidate differed from them. A candidate that matches either baseline when they disagree
doesn't count as different.

| Situation | Decision | Finding |
|---|---|---|
| Baselines never disagreed, and the candidate differs | Not noise | `value_changed` |
| Fewer than `min_observations` comparisons (3) | `insufficient_evidence` | `insufficient_baseline_evidence` |
| Candidate rate within `margin` (0.2) of the baseline rate | `explained` | `noise_explained` |
| Larger gap, and the 95% Wilson intervals of the two rates don't overlap | `exceeded` | `value_changed_beyond_noise` |
| Larger gap, but the intervals overlap | `insufficient_evidence` | `insufficient_baseline_evidence` |

The report's `noise` section lists every decision with its counts and rates. To resolve
uncertainty, replay more traffic on the route. Requests for different IDs on the same route
count toward the same fields.

If the baselines disagree on a field's presence or type, it's reported as uncertain. A
candidate missing a field both baselines have, or with a type neither has, is still breaking.

## Routes

Records are grouped into routes such as `GET /v1/orders/*`. Patterns in `routes` are tried
first: `*` matches one segment, a trailing `**` any remainder, and a method of `*` any method.
Otherwise, a path segment containing a digit is treated as an ID, unless it looks like a
version such as `v1`. An ID with no digits becomes its own route with fewer observations, so
add a pattern for those. A gRPC route is its method, such as
`POST /fixture.orders.v1.OrderService/GetOrder`, and IDs aren't guessed in it.

## Rules

```yaml
routes: ["GET /v1/orders/*"]
ignore:
  - route: "GET /v1/orders/*"
    paths: ["$.server_time", "$.items[*].updated_at"]
    types: [string]          # Optional: only differences of these types.
  - route: "GET /v1/legacy"
    paths: ["$.debug"]
    ignore_structure: true   # Must be explicit: also hides removals and type changes.
unordered_arrays:
  - route: "GET /v1/catalog"
    paths: ["$.items"]
compare_headers: [Cache-Control]
evidence: values             # Or types, to keep values out of reports.
noise: {min_observations: 3, margin: 0.2}
latency: {percentiles: [50, 95, 99], min_samples: 20, max_increase_percent: 20, min_increase_ms: 5}
error_rate: {min_requests: 20, max_increase_points: 1}
limits: {max_routes: 1000, max_fields_per_route: 2000, max_findings: 1000, max_evidence_bytes: 120}
```

Pass it with `--diff-config`. The values shown are the defaults, and unknown keys are errors.
Field paths use normalized array indexes (`$.items[*].id`), and a rule covers everything under
its path. **An ignore rule covers values only**, unless `ignore_structure` is set. The report's
`ignored` section lists what each rule suppressed.

## Latency

Latency is compared only on records that succeeded on all three targets. Each record reached
all three at the same time, so they saw comparable load. It's measured from sending the
request to reading the whole response, and includes opening a connection, because replay
doesn't reuse them. Each target's percentiles use the nearest-rank method over its own
samples, of which up to 4096 are kept per route and target, replaced at random beyond that.

A route regresses when, at a percentile, the candidate exceeds the slower baseline by more
than `max_increase_percent` and by at least `min_increase_ms`, so tiny absolute changes don't
count. Below `min_samples`, a route's latency isn't evaluated, and the report's `routes`
section says so.

## Error rate

Errors are 5xx responses and failed calls, plus gRPC server faults as listed under
[gRPC status](#grpc-status). A route regresses when the candidate's rate exceeds the
baselines' by more than `max_increase_points` percentage points, with at least `min_requests`
records.

## Evidence and limits

Each finding cites the example with the lowest sequence number, with each target's type and
value, and `present` tells a missing field from a null one. Values come from sanitized
responses and are cut to `max_evidence_bytes`. Findings are sorted by severity, route, path and
kind, so output doesn't depend on the order responses arrived in.

Reaching a limit never hides anything silently:

- Past `max_findings`, the list is cut with the most severe first, the severity counts stay
  complete, and `truncated` says how many were left out.
- Past `max_fields_per_route` or `max_routes`, an uncertain notice appears in `limited`, the
  extra fields aren't checked, and the extra routes are grouped under `(other routes)`. `run`
  exits 2 and the gate can't pass. Raise the limit to resolve it.

## Known limits

- A candidate value that's wrong but always different, on a field that also always differs
  between baselines, looks like noise. A frozen timestamp is one example. Structure is still
  checked.
- Coarse timestamps can differ between targets only occasionally. If the baselines happen to
  agree each time, that shows as `value_changed`, so add an ignore rule for fields like these.
- Secret-like values the redaction policy doesn't cover can appear in evidence. Use
  `evidence: types` if that's a concern, and see [redaction limits](redaction.md#known-limits).
- Object keys appear in field paths and aren't redacted. So do protobuf map keys, in evidence.
