# ADR 0009: gRPC is read with a descriptor set

Status: accepted

## Context

gRPC bodies are binary Protocol Buffers. Without the schema, a message is a list of numbered fields
with no names or types, so rules can't name what to redact and comparison can't tell a removed field
from a changed one. The schema has to come from somewhere, and it has to be the same one at capture,
at replay and when comparing, or the same bytes could mean different things.

gRPC also sends every method as POST, so the HTTP method says nothing about whether a call is safe to
repeat.

## Decision

- Read messages with a compiled descriptor set supplied as a file, built by `protoc` with
  `--include_imports`. It can be reviewed and versioned alongside the policy.
- Store the set's digest in each gRPC record, and skip records whose digest differs from the set given
  to `run`.
- Fail closed when a message can't be fully interpreted. Unknown fields, an `Any` of a type outside the
  set, malformed bytes, more than one message, and a missing set all omit the body, because no rule
  can see into bytes the schema doesn't describe.
- Name redaction rules by full field name, so they follow a message type wherever it appears rather
  than a path that a schema change could move.
- Replay a gRPC call only if `--allow-rpc` names its method. The list is checked against the set at
  startup, and streaming methods are refused. Allowing POST never makes gRPC eligible.
- Send replayed calls with the standard HTTP client as one uncompressed message, so every target gets
  the same sanitized bytes and no client library adds retries, hedging or compression of its own.
- Compare by protobuf's presence rules. A field that has presence can be removed, and an ordinary
  scalar changes to its default, since the wire format can't tell unset from default.
- Treat a new gRPC error where the baselines answered, or a new server fault, as breaking, and count
  server faults toward the error rate, since gRPC reports them over HTTP 200.
- Decode untrusted bytes through a guard that turns a decoder panic into an error. protobuf-go was seen
  to panic on one malformed map entry.

## Alternatives considered

**Server reflection.** It needs a live, reachable server with reflection enabled, which production
services often disable. The schema could also change between capture and replay without anyone
noticing, and the proxy would gain a network dependency.

**Generated code.** It would tie the tool to one service's schema at build time. replaydiff has to
work with any service.

**Treating messages as opaque bytes.** Bytes can't be redacted by rule, so nothing could be stored,
and comparison could only say "different".

**A gRPC client library for replay.** It would bring retry policies, compression negotiation and its
own encoding, so what reached a target could differ from what was stored.

**Storing unknown fields.** Redaction can't see into them, so this would store data that no rule
protects.

## Consequences

- Users must build and supply the descriptor set, and keep it matched to the recordings.
- A server newer than the set can add fields, which makes its messages unknown-field bodies. Captured
  responses aren't stored then, though replay still compares fresh ones, where unknown fields are
  compared by presence. Captured requests aren't replayable until the set is updated.
- Streaming calls are forwarded but not stored or replayed.
- Replay can't exercise a client's gRPC retry behavior, which is outside what it tests.
