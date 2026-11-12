# CI gate

`replaydiff report` applies a policy to a run's findings and sets the exit code.

```bash
replaydiff run --traffic ./traffic --redact redact.yaml --report report.json ...
replaydiff report report.json --policy policy.yaml \
  --markdown summary.md --junit junit.xml --json gate.json
```

`run` says whether the evidence is complete, and **`report` is the gate**. Let it run even if
`run` failed: with no report to read, it exits 2.

## Exit codes

These are a stable contract.

| Code | Verdict | Meaning |
|---|---|---|
| 0 | `pass` | The evidence is complete and the candidate meets the policy |
| 1 | `regression` | A finding fails the policy |
| 2 | `incomplete` | Invalid input, a failure, or evidence that can't support a conclusion |

A confirmed regression exits 1 even if some evidence is also missing, because it's real and
needs acting on. The output shows both.

### What stops a run from passing

Evidence is judged from the run's raw figures, not from its own claim. Any of these gives
exit 2 unless a regression was also found:

- The report is missing, unreadable or from another version, its figures disagree with each
  other, or it holds a kind of finding this build doesn't know.
- The dataset is damaged or incomplete in any way.
- No records were eligible, or fewer were compared than `min_compared`.
- The run was interrupted, or a record couldn't be read back.
- A call to a baseline failed.
- There were more uncertain findings than `max_uncertain`.
- A comparison limit was reached, so part of the evidence wasn't compared. No policy can allow
  this, because the fix is to raise the limit.
- Capture dropped more than `max_capture_drop_percent` of what it saw.
- A limit left findings out of the report, so they couldn't be judged.
- An output file couldn't be written.

**A report isn't tamper-proof.** These checks catch a damaged, stale or inconsistent file.
The report isn't signed, though, so anyone who can edit it could remove findings and correct
the totals. Run `run` and `report` in the same CI job, and treat a report from anywhere else
as a claim rather than evidence.

## Policy

Without `--policy`, breaking findings fail the build, and anything uncertain or any dropped
recording stops it from passing. [`examples/policy.yaml`](../examples/policy.yaml) shows every
setting, and unknown keys are errors.

```yaml
fail_on: [breaking, latency_regression]
evidence:
  min_compared: 20
  max_uncertain: 0
  allow_uncertain: [body_not_compared]
  max_capture_drop_percent: 1
  max_skipped_percent: 100
waivers:
  - route: "GET /v1/users/*"
    kinds: [value_changed]
    paths: ["$.display_name"]
    reason: "Display names are upper-cased on purpose in this release."
```

| Setting | Default | Meaning |
|---|---|---|
| `fail_on` | `[breaking]` | Severities and [kinds](diffing.md#severity) that are regressions. Must include `breaking`. |
| `evidence.min_compared` | 1 | Records that must have been compared |
| `evidence.max_uncertain` | 0 | Uncertain findings a pass may have |
| `evidence.allow_uncertain` | None | Uncertain kinds not counted against that limit. Reached limits can't be listed. |
| `evidence.max_capture_drop_percent` | 0 | Dropped recordings, out of all exchanges capture saw |
| `evidence.max_skipped_percent` | 100 | Skipped records, out of all readable ones |

`--fail-on breaking,warning` overrides `fail_on` for one invocation. A list without
`breaking` is refused, so adding to the default can't replace it by accident. To accept a
known breaking change, use a waiver.

**Small runs exit 2 at first.** With few requests per route, fields that vary can't be told
from real changes, and the output says `insufficient_baseline_evidence`. Replay more traffic
per route, or accept it knowingly with `allow_uncertain`.

### Waivers

A waiver accepts a known change on a route, for the listed kinds and optionally the listed
paths. It needs a `reason`, which appears next to the finding in every report. A waiver can't
excuse missing evidence, including any uncertain kind, because `allow_uncertain` is the
deliberate way to accept those. A waiver that matched nothing is listed as unused, since it
may be stale. Findings left out of the report past `max_findings` can't be waived.

## Output

| Flag | Format | Use |
|---|---|---|
| None | Text on stdout | Reading a build log. `--quiet` prints only the verdict. |
| `--markdown` | Markdown | Pull request and job summaries. Tables are capped at 100 rows. |
| `--junit` | JUnit XML | CI test views |
| `--json` | JSON with the decision and the whole run | Keeping everything, or further tooling |

In JUnit, a regression is a `failure`, missing evidence is an `error` because the check
couldn't finish, and a waived finding is `skipped`, with its reason.

Output files are written before the exit code is decided, so a failed build has its
explanation, and only their owner can read them. They hold sanitized evidence, but
[redaction only covers what its rules cover](redaction.md#known-limits), so treat them like
the recordings, or set `evidence: types` in the [comparison config](diffing.md#rules) to keep
values out. Routes and field names come from traffic, so they're escaped in every format, and
a request can't change a JUnit file's structure or inject HTML into a pull request summary.

## GitHub Actions

[`examples/github-actions/replay-gate.yml`](../examples/github-actions/replay-gate.yml) is
ready to adapt. A test checks that it gets these details right:

- The replay step has `continue-on-error: true`, so a failed replay still reaches the gate.
- The gate step doesn't, and its exit code isn't discarded, so it decides the job.
- The summary and report steps use `if: always()`, so they run when the gate fails.

This repository's CI runs `scripts/gate-demo.sh`, which proves each outcome against real
processes. Run it locally with `make gate-demo`.

## What the gate can't tell you

A pass means no covered finding failed the policy, on the traffic that was replayed. It
doesn't mean there are no bugs: traffic that wasn't captured or replayed isn't tested,
mutating requests are skipped by default, and [comparison has limits](diffing.md#known-limits).
