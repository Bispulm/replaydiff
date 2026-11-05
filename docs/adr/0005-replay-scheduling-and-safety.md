# ADR 0005: Fair, lockstep replay scheduling with no retries

Status: accepted

## Context

Replay has to keep each session's order at each target, let unrelated sessions make
progress, compare latencies fairly, and stay bounded. It also must not produce
surprising load or duplicate side effects.

## Decision

- **One record in flight per session.** The next record starts only after all three
  targets have finished the current one. This gives per-target ordering without
  tracking separate positions per target.
- **A FIFO of sessions.** A worker takes the front session, runs one record, and puts
  the session at the back. Round-robin needs no tuning, and a test checks for strict
  alternation.
- **All three calls start together**, so targets see the same concurrent load.
- **Take the per-target permit before the global one.** A saturated target then can't
  sit on global permits that other targets could use.
- **`--rps` counts logical records**, and the report states both rates.
- **No retries.** One record is exactly one call per target.
- **Two passes over the dataset.** `Scan` validates everything and builds an index, so
  unknown versions and damage are found before any traffic is sent, and arrival order
  can be restored. Bodies are loaded when needed.

## Alternatives considered

**Independent per-target queues.** A slow candidate wouldn't hold back the baselines,
but the targets would then see different load, which undermines latency comparison,
and results would need unbounded buffering to line up.

**Retrying failures.** This would hide flakiness that the tool exists to reveal, and
invisibly change the load and side effects.

**Skipping a failed baseline's records silently.** This could turn a broken baseline
into a passing run. Any baseline failure makes the evidence incomplete instead.

## Consequences

- A slow target slows every session, by design. The timeout bounds how much.
- A session with many records holds an active slot for its whole length, and sessions
  beyond the limit wait for a free slot.
- The index needs memory per record, so datasets have an explicit size limit, and
  exceeding it is an error rather than a silently replayed prefix.
