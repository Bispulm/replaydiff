# Benchmarks

These targets were set before anything was measured, so that results are judged against
them rather than chosen to fit. Results are added below with the machine, versions, commit,
commands and anything else that was running. A missed target is reported as missed.

## Targets

| Measure | Workload | Target |
|---|---|---|
| Latency capture adds, proxied minus direct | 500 req/s open loop, 16 connections, 1 KiB JSON responses, 30 s per phase | p50 at most 1 ms, p99 at most 5 ms |
| Capture drops | 1,000 req/s for 60 s, 1 KiB bodies, default limits | None |
| Highest sustainable recording rate | Increasing rate steps of 20 s, 1 KiB bodies | At least 2,000 req/s with no drops, p99 added at most 10 ms, and 95% of the offered rate achieved |
| Capture peak memory | The 1,000 req/s run | Resident set at most 300 MiB with the default 256 MiB body budget |
| Replay rate | 3,000 records against local targets, default concurrency | At least 300 records/s, which is 900 target calls/s |
| Fairness | One 1,000-record session and 50 five-record sessions | Every short session finishes within the first 30% of the run |
| Allocations | Go benchmarks of proxying, redaction, encoding and comparison | Reported, with no target |

## Method

**Open loop.** Requests are scheduled at fixed intervals, and latency is measured from when a
request was due, not when a free connection picked it up. A slow server can't lower the load
it receives, so queueing shows up as latency rather than being hidden.

**Direct and proxied phases alternate**, several rounds each, against the same upstream, so
drift on the machine affects both. The upstream is a minimal server returning a fixed body,
so its own cost is small and constant.

**Capture runs as its own process**, as deployed, writing to a local disk. Drops come from its
metrics, and its peak resident set comes from the operating system when it exits.

**Replay and fairness** use the replay engine against local targets that answer at once, so
they measure scheduling and the client rather than a service.

**Other workloads.** The machine is shared. Measurements hold a lock that other heavy jobs
respect, and record the load average before and after. Anything that couldn't be excluded is
stated with the result.
