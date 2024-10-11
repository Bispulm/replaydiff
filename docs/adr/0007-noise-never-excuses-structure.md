# ADR 0007: Noise explains values, never structure

Status: accepted

## Context

Comparing a candidate against one baseline flags every timestamp and generated ID. Comparing two
baselines, as Diffy does, shows which fields vary on their own. The trap is treating a field that
varies as a field to ignore: if `stock_estimate` is noisy, a candidate that turns it into a string or
removes it must still be caught. Those are exactly the changes that break clients.

## Decision

- Compare three trees position by position. Check presence and type before values, without
  looking at the values.
- Track each field per route. A noise decision covers only value differences on that route.
- Compare the baseline disagreement rate with the candidate difference rate.
- A gap larger than the margin needs non-overlapping 95% Wilson intervals to count as a change. If the
  intervals overlap, or there are too few observations, the finding is `uncertain`.
- Make `uncertain` its own severity, so CI policy has to take a position on it.
- Sanitize responses first, so all comparison and evidence work from sanitized data.
- Keep counts and one example per finding rather than bodies, so memory doesn't grow with traffic.
- Keep severity separate from CI policy.

## Alternatives considered

**A field is noise once the baselines ever disagree.** This is simple, but one chance disagreement
would hide a real change on that field for the whole run.

**A fixed margin between the rates.** This was the first version. A real run exposed the flaw: baseline
timestamps collided on the same microsecond, and two collisions in five comparisons would give rates of
0.6 and 1.0, a false warning on a timestamp. The gap means little on five observations. Wilson intervals
behave sensibly at rates of 0 and 1 and on few observations, where these decisions are made.

**Repeating requests to the baselines to gather more evidence.** This would resolve uncertainty sooner,
but it adds calls that a reader of the load numbers wouldn't expect. Grouping records by route already
gives repeated observations. It can be added as an explicit option if real use shows a need.

**Treating too few observations as a pass, or as a failure.** A pass pretends uncertainty is evidence. A
failure would make small runs useless. Reporting it leaves the decision to the policy.

## Consequences

- Removed and retyped fields are found on noisy routes, and a test requires this.
- Small runs produce uncertain findings until they have more traffic. That's accurate, and it may
  surprise people.
- A candidate that differs at about the same rate as noisy baselines looks like noise, including a frozen
  timestamp.
- Redacted fields can't be compared by value.
