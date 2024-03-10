# CI gate

`replaydiff report` applies a policy to a run's findings and sets the exit code.

```bash
replaydiff run --traffic ./traffic --redact redact.yaml --report report.json ...
replaydiff report report.json --policy policy.yaml \
  --markdown summary.md --junit junit.xml --json gate.json
```

`run` says whether the evidence is complete. **`report` is the gate.** Use its exit code to
decide a build, and let it run even if `run` failed: with no report to read, it exits 2.

## Exit codes

These are a stable contract.

| Code | Verdict | Meaning |
|---|---|---|
| 0 | `pass` | The evidence is complete and the candidate meets the policy |
| 1 | `regression` | A finding fails the policy |
| 2 | `incomplete` | Invalid input, a failure, or evidence that can't support a conclusion |

A confirmed regression exits 1 even if some evidence is also missing, because it's real and
it's what someone needs to act on. The output shows both.

### What stops a run from passing

Evidence is judged from the run's raw figures and not from its own claim, so editing
`evidence_complete` in a report changes nothing. Any of these give exit 2 unless a regression
was also found:

- The report is missing, unreadable, or from another version.
- The dataset is damaged or incomplete in any way.
- There were no eligible records, or fewer compared than `min_compared`.
- The run was interrupted, or a record couldn't be read back.
- Any call to a baseline failed.
- More uncertain findings than `max_uncertain`, including reached limits.
- Capture dropped more than `max_capture_drop_percent` of what it saw.
- Findings were left out of the report by a limit, so they couldn't be judged.
- An output file couldn't be written.

## Policy

Without `--policy`, breaking findings fail the build, and anything uncertain or any dropped
recording stops it from passing. [`examples/policy.yaml`](../examples/policy.yaml) shows every
setting. Unknown keys are errors.

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
| `fail_on` | `[breaking]` | Severities and [kinds](diffing.md#severity) that are regressions |
| `evidence.min_compared` | 1 | Records that must have been compared |
| `evidence.max_uncertain` | 0 | Uncertain findings a pass may have |
| `evidence.allow_uncertain` | None | Uncertain kinds not counted against that limit |
| `evidence.max_capture_drop_percent` | 0 | Dropped recordings, out of all exchanges capture saw |
| `evidence.max_skipped_percent` | 100 | Skipped records, out of all readable ones |

`--fail-on breaking,warning` overrides `fail_on` for one invocation.

**Small runs will exit 2 at first.** With few requests per route, fields that vary can't be told
from real changes, and the output says `insufficient_baseline_evidence`. Replay more traffic per
route, or allow it knowingly with `allow_uncertain`.

### Waivers

A waiver accepts a known change on a route, for the listed kinds and optionally the listed paths.

- A `reason` is required, and it appears in every report next to the finding.
- A waiver can't excuse missing evidence, because it's about a known change and not an unknown one.
- A waiver that matched nothing is listed as unused, since it may be stale.

Waivers apply only to findings in the report's list. Past `max_findings`, the rest can't be waived.

## Output

| Flag | Format | Use |
|---|---|---|
| None | Text on stdout | Reading a build log. `--quiet` prints only the verdict. |
| `--markdown` | Markdown | Pull request and job summaries. Tables are capped at 100 rows. |
| `--junit` | JUnit XML | CI test views |
| `--json` | JSON with the decision and the whole run | Keeping everything, or further tooling |

In JUnit, a regression is a `failure`, because the code under test is at fault. Missing evidence is
an `error`, because the check couldn't finish. A waived finding is `skipped`, with its reason.

Output files are written before the exit code is decided, so a failed build has its explanation.
They contain sanitized evidence, but [redaction only covers what its rules cover](redaction.md#known-limits),
so treat them with the same care as the recordings. Use `evidence: types` in the
[comparison config](diffing.md#rules) to keep values out of them. Files are readable only by their owner.

Routes and field names come from traffic, so they're escaped in every format. A request can't change a
JUnit file's structure, or inject HTML into a pull request summary.

## GitHub Actions

[`examples/github-actions/replay-gate.yml`](../examples/github-actions/replay-gate.yml) is ready to adapt.
Getting these details right matters, and a test checks the example has them:

- The replay step has `continue-on-error: true`, so a failed replay still reaches the gate.
- The gate step doesn't, and its exit code isn't discarded, so it decides the job.
- The summary and report steps use `if: always()`, so they run when the gate fails.

This project's own CI runs `scripts/gate-demo.sh`, which proves each outcome against real processes.
Run it locally with `make gate-demo`.

## What the gate can't tell you

A pass means no covered finding failed the policy, on the traffic that was replayed. It doesn't mean
there are no bugs: traffic that wasn't captured or replayed isn't tested, mutating requests are skipped
by default, and [comparison has limits](diffing.md#known-limits).
