# Comparison

`replaydiff run` compares each record's responses from baseline A, baseline B and the
candidate. The results go in the report's `comparison` section.

**Severity isn't CI policy.** A finding says what was seen. Whether it fails a build is decided
by the [CI gate](ci.md).

## What is compared

Responses are sanitized with the redaction policy before anything else happens to them, so
that evidence can't hold values the policy covers. This means a redacted field's value and
type aren't compared, since all three targets show the same placeholder. Its presence is.

For each record, in this order:

1. **The call.** A failed baseline call means the record isn't compared, and the run's
   evidence is incomplete. A failed candidate call is a finding.
2. **Status.** A changed class stops the comparison of that record, because the bodies are
   no longer the same kind of response.
3. **Media type**, ignoring parameters such as `charset`.
4. **Headers** listed in `compare_headers`. Others aren't compared, because many vary by nature.
   Headers removed by sanitizing, such as `ETag` and `Content-Length`, are refused in the config,
   since they could never show a difference.
5. **The body.**

## Bodies

JSON bodies are compared by structure. Bodies of a type listed in `opaque_content_types`, and
form-encoded ones, are compared as a whole. Others can't be compared, and that is reported.

| Rule | Example | Result |
|---|---|---|
| Object key order doesn't matter | `{"a":1,"b":2}`, `{"b":2,"a":1}` | Equal |
| Numbers keep their precision | `12345678901234567890`, `12345678901234567891` | Different |
| Same number, written differently | `1.0`, `1` | Equal, reported as info |
| Missing isn't null | `{"a":null}`, `{}` | Field removed |
| Types are never coerced | `1`, `"1"` | Type changed |
| Array order matters, unless a rule says otherwise | `[1,2]`, `[2,1]` | Different |

Numbers are compared exactly, by value. Those with an exponent above 1000 or more than 512
characters are compared by their text, because exact comparison would be too expensive.

Array elements are compared by position, up to the shortest length, and a different length
is its own finding. Anything nested deeper than 64 levels is compared as a single value.

## Severity

| Severity | Meaning | Kinds |
|---|---|---|
| Breaking | The contract changed | `status_class_changed`, `field_removed`, `type_changed`, `candidate_call_failed`, `body_removed`, `body_invalid`, `body_type_changed` |
| Warning | Behavior changed, possibly on purpose | `value_changed`, `value_changed_beyond_noise`, `array_length_changed`, `status_changed`, `content_type_changed`, `latency_regression`, `error_rate_regression` |
| Uncertain | The evidence can't support a conclusion. **This isn't a pass.** | `insufficient_baseline_evidence`, `baseline_presence_unstable`, `baseline_type_unstable`, `baseline_status_unstable`, `baseline_content_type_unstable`, `baseline_body_unstable`, `body_not_compared`, `field_limit_reached`, `route_limit_reached` |
| Info | A permitted difference, or noise that was explained | `field_added`, `body_added`, `number_format_changed`, `noise_explained` |

## Noise

Baseline A and baseline B run the same code, so a field that differs between them varies for
reasons other than the code, such as a timestamp or a generated ID.

**Noise only ever explains differences in values.** Structure is checked first and separately,
so a field the candidate removed or retyped is breaking however much its value varies.

Each field is tracked separately per route and per JSON type, so noise on one route doesn't
excuse a change on another, and disagreement about a field's strings says nothing about a change
to its numbers. The decision compares two rates over all such comparisons:

- **Baseline rate:** how often A and B disagreed.
- **Candidate rate:** how often the candidate differed from them. A candidate matching either
  baseline when they disagree isn't counted as different.

| Situation | Decision | Finding |
|---|---|---|
| Baselines never disagreed, and the candidate differs | Not noise | `value_changed` |
| Fewer than `min_observations` comparisons (3) | `insufficient_evidence` | `insufficient_baseline_evidence` |
| Candidate rate within `margin` (0.2) of the baseline rate | `explained` | `noise_explained` |
| Larger gap, and the 95% Wilson intervals of the two rates don't overlap | `exceeded` | `value_changed_beyond_noise` |
| Larger gap, but the intervals overlap | `insufficient_evidence` | `insufficient_baseline_evidence` |

Every decision is listed in the report's `noise` section with its counts and rates.

More observations resolve uncertainty, so replay more traffic on the route. Records are grouped
by route, so requests for different IDs count toward the same fields.

If the baselines disagree on a field's presence or type, it can't be judged, and that is
reported as uncertain. The exceptions are a candidate missing a field both baselines have, or
having a type neither has, which are still breaking.

## Routes

Records are grouped into routes such as `GET /v1/orders/*`. Patterns in `routes` are tried first,
where `*` matches one segment, a trailing `**` any remainder, and a method of `*` any method.

Otherwise, a path segment containing a digit is treated as an ID, unless it looks like a version
such as `v1`. This is a heuristic: an ID with no digits becomes its own route, and gets fewer
observations. Add a pattern to group those.

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

Pass it with `--diff-config`. The values shown are the defaults. Unknown keys are errors.

Field paths use normalized array indexes (`$.items[*].id`), and a rule covers everything under
its path. **An ignore rule covers values only** unless `ignore_structure` is set. What each rule
suppressed is listed in the report's `ignored` section.

## Latency

- **Samples:** only records that succeeded on all three targets. Each was sent to all three at
  the same time, so they saw comparable load.
- **Percentiles:** nearest rank, meaning the smallest sample with at least that percentage of
  samples at or below it. Each target's percentile is computed from its own samples.
- **Reference:** the slower baseline at that percentile.
- **Regression:** the candidate exceeds the reference by more than `max_increase_percent` and by
  at least `min_increase_ms`. The second condition stops tiny absolute changes from counting.
- **Too few samples:** below `min_samples`, a route's latency isn't evaluated, and the report's
  `routes` section says so.

Latency is measured from sending the request to reading the whole response, and includes opening
a connection, because replay doesn't reuse them. Up to 4096 samples are kept per route and target,
replaced at random beyond that.

## Error rate

Errors are 5xx responses and failed calls. A route has a regression when the candidate's rate exceeds
the baselines' by more than `max_increase_points` percentage points, with at least `min_requests`
records.

## Evidence and limits

Each finding cites the example with the lowest sequence number, with each target's type and value.
`present` distinguishes a missing field from a null one. Values come from sanitized responses and are
cut to `max_evidence_bytes`. Findings are sorted by severity, route, path and kind, so output doesn't
depend on the order responses arrived in.

Reaching a limit never hides anything silently:

- Past `max_findings`, the list is cut, the severity counts stay complete, and `truncated` says how
  many were left out. The most severe findings come first.
- Past `max_fields_per_route` or `max_routes`, an uncertain notice appears in `limited`. Those fields
  aren't checked, and those routes are grouped together under `(other routes)`. `run` exits 2 and the gate
  can't pass, because part of the evidence wasn't compared. Raise the limit to resolve it.

## Known limits

- A candidate whose value is wrong but always different, on a field that also always differs between
  baselines, looks like noise. A frozen timestamp is one example. Structure is still checked.
- Coarse timestamps can differ between targets only occasionally, and if the baselines happen to agree
  each time, that shows as `value_changed`. Add an ignore rule for fields like these.
- Secret-like values the redaction policy doesn't cover can appear in evidence. Use `evidence: types`
  if that's a concern, and see [redaction limits](redaction.md#known-limits).
- Object keys appear in field paths and aren't redacted.
- Protobuf comparison is planned.
