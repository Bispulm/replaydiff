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

## Results, 2026-11-05

| Measure | Result | Target | Verdict |
|---|---|---|---|
| Latency capture adds at 500 req/s, median of 7 rounds | p50 +0.09 ms, p99 +0.30 ms | p50 at most 1 ms, p99 at most 5 ms | Met |
| Capture drops at 1,000 req/s for 60 s | 0 of 60,000, no errors | None | Met |
| Highest sustainable recording rate | 8,000 req/s, the highest step that passed | At least 2,000 req/s | Met |
| Capture peak resident set in the 1,000 req/s run | 41 MiB | At most 300 MiB | Met |
| Replay rate, 3,000 records | 7,040 records/s, 21,120 calls/s | At least 300 records/s | Met |
| Fairness | The last short session finished at 13% of the run | Within 30% | Met |

**Machine.** Apple M4 Pro, 14 CPUs, 24 GiB, macOS on arm64, Go 1.27.3. The load generator,
the upstream and capture shared the machine and talked over loopback, so no network latency
is included, and the three competed for CPU. Bodies were 1 KiB of JSON, every request was a
GET over HTTP/1.1, and capture applied one JSON-path rule. HTTP/2, gRPC and TLS weren't
measured.

**Other workloads.** Other builds and tests were running on the same machine throughout. The runs held a lock that kept other benchmarks and cluster tests out, but not
ordinary builds and tests. Load averages were recorded:

| Run | Commit | Load average before | After |
|---|---|---|---|
| All measurements | `29fe6f7` | 6.5, 10.6, 9.4 | 10.5, 12.2, 11.6 |
| Latency, repeated with 7 rounds | `0050fcb`, the same capture code | 5.3, 8.9, 10.3 | 7.7, 5.4, 7.8 |

In the first run, two of the three latency rounds were disturbed. One proxied phase reached a
p99 of 248 ms and one direct phase 132 ms, with neither tied to capture. Its median came from
the one quiet round, so latency was measured again with seven rounds, and that is the result
above. A 5-second test run of this project also overlapped the first run.

**Latency by round.** The added latency differs from round to round by more than its median,
in both directions, so the effect is smaller than this machine's noise. What the
measurement supports is that capture added well under a millisecond at the median here.

| Round | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|
| p50 added, ms | +0.40 | +0.09 | +0.09 | −0.20 | +0.41 | +0.09 | −0.05 |
| p99 added, ms | +1.08 | +0.30 | +0.25 | −1.21 | +0.50 | +0.26 | +1.59 |

**Rate steps.** Each step started a new capture process and offered the rate for 20 seconds.

| Offered req/s | Achieved | Recordings dropped | p99 direct, ms | p99 proxied, ms | Capture peak memory |
|---|---|---|---|---|---|
| 1,000 | 1,000 | 0 | 0.53 | 1.26 | 40 MiB |
| 2,000 | 2,000 | 0 | 0.75 | 2.04 | 42 MiB |
| 4,000 | 4,000 | 0 | 0.22 | 0.29 | 42 MiB |
| 8,000 | 8,000 | 0 | 0.12 | 0.38 | 45 MiB |
| 16,000 | 16,000 | 6,286 of 320,000, all `queue_full` | 1.18 | 31.24 | 68 MiB |

At 16,000 req/s every request was still forwarded without error. Recordings were dropped
rather than traffic delayed, as designed, but p99 rose by 30 ms. The search stopped there.

**Replay and fairness** used the replay engine against local targets that answer at once,
with default concurrency (32 calls, 16 per target, 256 active sessions). Real services would
be far slower than these targets, so the replay rate shows that replay itself isn't a
bottleneck, not what a run against real services would achieve.

**Go benchmarks**, median of 5 runs each, from `make bench`:

| Benchmark | Time | Memory | Allocations |
|---|---|---|---|
| Request, direct | 42.5 µs | 6.0 KB | 69 |
| Request, through capture | 81.9 µs | 57 KB | 229 |
| Redact a 1 KiB JSON body | 21.0 µs | 17.7 KB | 294 |
| Redact a 64 KiB JSON body | 1.20 ms | 1.1 MB | 16,673 |
| Encode a record | 6.6 µs | 4.4 KB | 8 |
| Compare one JSON record three ways | 193 µs | 182 KB | 3,017 |

The request benchmark is serial and includes the recording work capture does in the
background, so its 39 µs difference approximates what capture costs per request on this
machine, the extra hop included. A captured request allocates about ten times as much as a direct one, mostly in
body capture and encoding. Nothing has been optimized, since every target was met.

**Commands.**

```bash
make build
bin/replaydiff-bench --capture bin/replaydiff --out .bench
bin/replaydiff-bench --capture bin/replaydiff --only latency --rounds 7 --out .bench/latency
make bench
```

**Limits.** One machine, loopback only, small synthetic GET requests, and a load generator
sharing the CPU. These results show the design holds its bounds under load. They don't
predict latency or capacity in production, which depend on the network, body sizes, the
policy and the service. Measure in your own environment.
