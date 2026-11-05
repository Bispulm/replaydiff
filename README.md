# replaydiff

replaydiff captures service traffic through a reverse proxy, redacts it before
storage, and replays it against two baselines and a candidate. Comparing the responses
and acting as a CI gate are the next milestones.

**Status: early development, not ready for production use.**

| Area | State |
|---|---|
| HTTP/1.1 and HTTP/2 capture proxy, bounded and non-blocking | Implemented and tested |
| Rule-based redaction before storage | Implemented and tested |
| Recoverable, versioned traffic format | Implemented and tested |
| Allowlisted, session-ordered replay with rate limits | Implemented and tested |
| Synthetic fixtures with deliberate regressions | Implemented |
| JSON and protobuf diffing, noise handling | Planned |
| CI reports (JSON, JUnit, Markdown) and policy | Planned |
| Unary gRPC | Planned |
| Helm sidecar, metrics, traces | Planned |
| Overhead and throughput benchmarks | Planned. No performance numbers are claimed yet. |

**`replaydiff report` currently always exits 2.** Responses aren't compared yet, and a CI
job shouldn't be able to pass on a replay nobody checked.

## Try it

Requires Go 1.27, `curl` and `python3`. Everything runs on `127.0.0.1` using invented
data, on ports 18200 to 18204.

```bash
make demo
```

The demo captures traffic holding planted secrets, prints a stored record, searches every
artifact for those secrets, replays against two baselines and a candidate, and shows a
target being refused for not being on the allowlist.

## How it works

```bash
# Capture: forwards live traffic and stores sanitized records.
replaydiff capture --listen :18200 --upstream http://127.0.0.1:18204 \
  --out ./traffic --redact examples/redact.yaml

# Review what was stored.
replaydiff inspect --traffic ./traffic

# Replay: only allowlisted origins, only read-only methods by default.
replaydiff run --traffic ./traffic --report report.json \
  --baseline-a http://127.0.0.1:18201 --baseline-b http://127.0.0.1:18202 \
  --candidate http://127.0.0.1:18203 \
  --allow-origin http://127.0.0.1:18201 \
  --allow-origin http://127.0.0.1:18202 \
  --allow-origin http://127.0.0.1:18203
```

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
- **Incomplete evidence can't exit 0.** That includes zero eligible records, a damaged
  dataset, a failed baseline, and an interrupted run.

## Documentation

- [Architecture](docs/architecture.md)
- [Traffic format](docs/traffic-format.md)
- [Redaction](docs/redaction.md)
- [Replay](docs/replay.md)
- [Protocols](docs/protocols.md)
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
