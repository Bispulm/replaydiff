# Related tools

Checked on 2026-11-05 against each project's own README and documentation.
Anything not listed here was not checked, so nothing below claims that a tool
lacks a feature.

## GoReplay

Source: [probelabs/goreplay](https://github.com/probelabs/goreplay) README and `docs/`.

- Its documented primary mode listens on network interfaces in the background
  rather than acting as a proxy (`--input-raw`, typically run with `sudo`).
- Saves traffic to files and replays it to an HTTP output, preserving the
  original timing between requests.
- Filters by URL, header and method, and rewrites URLs, params and headers.
- Handles custom logic, documented examples include stripping private data,
  through a middleware program that reads and writes over STDIN and STDOUT.
- Documents binary protocol support, including Protocol Buffers, as a PRO
  feature.

## Diffy

Source: [opendiffy/diffy](https://github.com/opendiffy/diffy) README.

- Acts as a proxy that multicasts each request to a candidate, a primary and a
  secondary, where primary and secondary run the same known-good code.
- Treats primary and secondary disagreement as noise. **replaydiff's two-baseline
  comparison uses the same established idea; it is not original to this project.**
- Reports a verdict through a web UI with endpoint, noise, transformation and
  run history views.
- Its source is under CC BY-NC-ND. No code from it is used here.

## How replaydiff is positioned

replaydiff is an engineering project built around specific guarantees, each of
which has automated tests:

- Redaction is a persistence invariant, enforced in-process before any write,
  and failing closed when a body can't be parsed.
- Live traffic never waits for storage. Recording drops are counted by reason.
- The recording format is bounded and recoverable, and damage to it is reported
  rather than hidden.
- Incomplete evidence can't produce a passing exit code.

The README lists what is implemented today. Features that aren't built yet are
marked as planned.
