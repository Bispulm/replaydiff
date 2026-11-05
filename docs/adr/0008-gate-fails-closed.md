# ADR 0008: The gate has three outcomes and fails closed

Status: accepted

## Context

A CI gate that passes when it shouldn't is worse than no gate, because people stop looking. The risky
cases aren't regressions. They're the runs where nothing was really checked: no eligible traffic, a dead
baseline, a damaged recording, or findings cut off by a limit. Each of those could look like "no findings".

## Decision

- Use three outcomes: 0 pass, 1 regression, 2 incomplete. Keeping regressions apart from incomplete evidence
  tells people whether to look at their code or at the check.
- A regression outranks incomplete evidence, since a confirmed one is real however much else is missing.
- Keep `run` and `report` separate. `run` gathers evidence and doesn't judge it, and its file says
  `not_evaluated`, so finishing a replay can't be mistaken for passing.
- Judge evidence from the raw figures, and not from the report's own claim. A finding's severity comes
  from its kind, and figures that disagree with each other can't pass.
- Default to strict. Uncertainty and dropped recordings stop a pass until a policy allows them.
- Require a reason for waivers, keep them visible, and don't let them excuse missing evidence.
- Let nothing in a policy accept a reached limit, because the fix is to raise it.
- Refuse a `fail_on` list without `breaking`, because adding to the default mustn't be able to replace it.
- Treat findings cut off by a limit as unjudged, so a long list can't hide a failure.
- Write output before setting the exit code, and fail if it can't be written.

## Alternatives considered

**Two outcomes, pass and fail.** Simpler, but people can't tell a broken candidate from a broken check, and
broken checks train them to ignore the result.

**Incomplete outranks regression.** This would bury a real finding under an infrastructure problem.

**Passing on uncertainty by default.** Small runs would be friendlier, but a gate that passes when it doesn't
know is the failure this design exists to prevent. Allowing it takes one line of policy.

**Having `run` apply the policy too.** It would save a step, but it mixes gathering evidence with judging it,
and re-judging the same evidence under another policy would need another replay.

## Consequences

- New users with small datasets see exit 2 until they add traffic or allow uncertainty. The output says why.
- Any dropped recording stops a pass by default, even a tiny number. Busy captures need a threshold.
- A waiver works per route, so a route that is reworked may need its waiver updated. Unused ones are reported.
- A pass only speaks for the traffic that was replayed. The docs say so.
- Reports aren't signed. The consistency checks catch damaged, stale and inconsistent files, not deliberate
  forgery, which would need signing and a key the job's other steps can't reach. Running `run` and `report` in
  one job is the practical protection.
