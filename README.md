# replaydiff

replaydiff captures service traffic through a reverse proxy, redacts it before storage,
replays it against two baselines and a candidate, and fails your CI build if the candidate
regressed. Using two baselines separates real changes from noise such as timestamps and
generated IDs.

**Status: early development, not ready for production use.**

| Area | State |
|---|---|
| HTTP/1.1 and HTTP/2 capture proxy, bounded and non-blocking | Implemented and tested |
| Rule-based redaction before storage | Implemented and tested |
| Recoverable, versioned traffic format | Implemented and tested |
| Allowlisted, session-ordered replay with rate limits | Implemented and tested |
| Synthetic fixtures with deliberate regressions | Implemented |
| JSON comparison, noise handling, latency and error-rate checks | Implemented and tested |
| Protobuf comparison | Planned |
| CI gate with a policy, JSON, JUnit and Markdown reports | Implemented and tested. The workflow hasn't run on GitHub yet. |
| Unary gRPC | Planned |
| Helm sidecar, metrics, traces | Planned |
| Overhead and throughput benchmarks | Planned. No performance numbers are claimed yet. |

## Try it

Requires Go 1.27, `curl` and `python3`. Everything runs on `127.0.0.1` using invented
data, on ports 18200 to 18204.

```bash
make demo
```

The demo captures traffic holding planted secrets, prints a stored record, searches every
artifact for those secrets, and replays against two baselines and a candidate. It then
lists what the candidate's deliberate regressions look like, with timestamps and IDs
explained as noise, and shows a target being refused for not being on the allowlist.

## How it works

```bash
# Capture: forwards live traffic and stores sanitized records.
replaydiff capture --listen :18200 --upstream http://127.0.0.1:18204 \
  --out ./traffic --redact examples/redact.yaml

# Review what was stored.
replaydiff inspect --traffic ./traffic

# Replay and compare: only allowlisted origins, only read-only methods by default.
replaydiff run --traffic ./traffic --report report.json --redact examples/redact.yaml \
  --baseline-a http://127.0.0.1:18201 --baseline-b http://127.0.0.1:18202 \
  --candidate http://127.0.0.1:18203 \
  --allow-origin http://127.0.0.1:18201 \
  --allow-origin http://127.0.0.1:18202 \
  --allow-origin http://127.0.0.1:18203

# Apply the CI policy. Exit 0 passes, 1 is a regression, 2 means the evidence is incomplete.
replaydiff report report.json --markdown summary.md --junit junit.xml
```

## Using it in CI

| Exit code | Verdict | Meaning |
|---|---|---|
| 0 | `pass` | The evidence is complete and the candidate meets the policy |
| 1 | `regression` | A finding fails the policy |
| 2 | `incomplete` | Invalid input, a failure, or evidence that can't support a conclusion |

`make gate-demo` proves all three against real processes. See the [CI guide](docs/ci.md) for the
policy, waivers and a GitHub Actions example.

## Guarantees and their limits

- **Live traffic doesn't wait for storage.** Recording failures drop recordings and count
  them by reason. The proxy does add some processing overhead, which hasn't been measured.
- **Covered values aren't persisted.** Tests plant unique values in every covered location
  and scan segments, logs and reports. **Redaction is rule-based and doesn't find unknown
  secrets.** Read [what it covers and what it can't](docs/redaction.md).
- **Damage is never silent.** Corruption costs at most the affected record and is always
  reported. A test flips every byte of a segment to confirm this.
- **A replay can't be aimed by its recording.** Destinations come only from configuration.
  See [replay](docs/replay.md).
- **Noise never excuses structure.** A field the candidate removed or retyped is breaking
  however much its value varies between baselines. Too little evidence is reported as
  uncertain, not as a pass. See [comparison](docs/diffing.md) for how this works and what it
  can't catch.
- **Incomplete evidence can't pass.** That includes zero eligible records, a damaged dataset, a
  failed baseline, an interrupted run, and a report whose figures disagree. Reports aren't signed, so
  this doesn't stop deliberate forgery. A pass only speaks for the traffic that was replayed.

## Documentation

- [Architecture](docs/architecture.md)
- [Traffic format](docs/traffic-format.md)
- [Redaction](docs/redaction.md)
- [Replay](docs/replay.md)
- [Protocols](docs/protocols.md)
- [Comparison](docs/diffing.md)
- [CI gate](docs/ci.md)
- [Fixtures](docs/fixtures.md)
- [Related tools](docs/related-tools.md)
- [Decision records](docs/adr/)

## Development

```bash
make build   # builds into ./bin
make test
make check   # lint, race tests, vulnerability and secret scans
```

## License

Apache-2.0. See [LICENSE](LICENSE).
