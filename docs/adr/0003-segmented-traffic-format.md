# ADR 0003: Checksummed segments with one compressed frame per record

Status: accepted

## Context

Recordings have to survive crashes and partial damage, and damage has to be
visible. A corrupt stretch must not make a CI gate pass, and it shouldn't lose
the whole file either. A single compressed stream can't be resumed after damage.

## Decision

- Store records in rotating segment files, each with its own header and footer.
- Compress each record as its own zstd frame.
- Protect each frame header and payload with separate CRC-32C checksums.
- Mark frame boundaries with a random per-segment sync marker.
- Encode records as JSON, with unknown fields rejected.
- Read in two passes: `Scan` validates everything and builds an offset index,
  then `Load` reads records on demand.

## Alternatives considered

**A batch of records per compressed frame.** The ratio is better, but one
damaged byte loses the whole batch, and a crash loses whatever is unflushed.
This can be revisited if measurements show the per-record ratio is a real cost.

**A fixed magic number instead of a random sync marker.** Response bodies are
attacker-influenced and may be stored uncompressed if incompressible. A fixed
marker could let a body forge a frame during recovery.

**Protobuf records.** More compact, but a debugging format needs to be easy to
inspect, and zstd already removes most of JSON's overhead.

## Consequences

- One flipped byte costs at most one record, and it's always reported. A test
  flips every byte of a segment to confirm this.
- Unknown versions and damage are found before any traffic is sent.
- Scan decompresses every record, so startup cost grows with dataset size, and
  the index holds a small entry per record. The default limit is one million
  records.
- `Load` opens the segment for every record. This is simple and has no file
  descriptor limit to manage, and it may need a cache if benchmarks show a cost.
