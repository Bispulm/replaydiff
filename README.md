# replaydiff

replaydiff captures service traffic through a reverse proxy, redacts it before
storage, replays it against two baselines and a candidate, and reports behavior
changes for use as a CI gate.

**Status: early development.** See [Status](#status) for what works today.

## Status

| Area | State |
|---|---|
| CLI skeleton and exit codes | Implemented |
| Synthetic fixtures with deliberate regressions | Implemented ([details](docs/fixtures.md)) |
| Capture, redaction, traffic format | Planned |
| Replay | Planned |
| JSON and protobuf diffing, noise handling | Planned |
| CI reports (JSON, JUnit, Markdown) | Planned |
| HTTP/2 and unary gRPC | Planned |
| Helm sidecar, metrics, traces | Planned |

Commands that aren't implemented yet exit with code 2, so they can't pass a CI
job by accident.

## Development

Requires Go 1.27.

```bash
make build   # builds into ./bin
make test
make check   # lint, race tests, vulnerability and secret scans
```

## Related tools

See [docs/related-tools.md](docs/related-tools.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
