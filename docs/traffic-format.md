# Traffic format

Format version 1, record schema version 1.

A dataset is a directory of segment files. Each segment can be read without any
other, and each record can be read without any other record in its segment.

## Files

| Item | Rule |
|---|---|
| Directory | Created with mode `0700`. An existing directory keeps its mode. |
| Segment | Mode `0600`, created with `O_EXCL` |
| Name | `<run-id>-<index>.rdt.open` while being written, renamed to `.rdt` once sealed |
| Rotation | At the first append after the segment reaches 64 MiB (configurable) |

Readers trust headers, not names. They consider only regular files with a
segment suffix, and they don't follow symlinks. No path inside a record is ever
used to open a file.

## Layout

All integers are big-endian. CRCs are CRC-32C.

### Segment header (52 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Magic `RDTRAFFC` |
| 8 | 2 | Format version |
| 10 | 2 | Reserved |
| 12 | 8 | Sync marker, random per segment |
| 20 | 16 | Run ID, random per capture run |
| 36 | 4 | Segment index within the run |
| 40 | 8 | Creation time, Unix nanoseconds |
| 48 | 4 | CRC of bytes 0 to 47 |

### Frame header (28 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Sync marker, same as the segment header |
| 8 | 1 | Kind: 1 record, 2 footer |
| 9 | 1 | Codec: 0 none, 1 zstd |
| 10 | 2 | Reserved |
| 12 | 4 | Stored payload length |
| 16 | 4 | Uncompressed payload length |
| 20 | 4 | CRC of the stored payload |
| 24 | 4 | CRC of bytes 0 to 23 |

The payload follows immediately. A record payload is one JSON document
compressed as its own zstd frame. Compressing per record costs some ratio, and
in exchange a damaged record can't affect any other.

### Footer

The last frame of a sealed segment. Its payload is
`{"record_count": N, "final": bool, "drops": {"reason": N}}`. `final` is true on
the last segment of a run that shut down cleanly. `drops` counts exchanges that
capture never recorded, by reason, and appears only on a final footer. Those
records are absent rather than damaged, so readers report them as a coverage gap.

## Record

Defined by `traffic.Record`. Bodies hold sanitized, decompressed content, and
JSON encodes them as base64. A body is always in exactly one state:

| State | Meaning | Data |
|---|---|---|
| `present` | Sanitized content is stored | Yes |
| `empty` | Observed, and had no bytes | No |
| `omitted` | Observed, and deliberately not stored. See `reason`. | No |
| `truncated` | Ended early on the wire | No |
| `unavailable` | Never observed | No |

`seq` is assigned when the request arrives. Files are written in completion
order, so `seq` is what restores arrival order within a run. Runs are ordered by
their earliest segment creation time.

## Limits

| Limit | Value |
|---|---|
| Stored or uncompressed frame, hard limit | 64 MiB |
| Footer, stored or uncompressed | 4 KiB |
| Encoded record when writing, default | 16 MiB |
| Index size when reading, default | 1,000,000 records |
| Path, query | 64 KiB each |
| Headers per message | 512 |

A frame's declared uncompressed size is checked against the limit before
allocating, and the output must match it exactly. Checksums are not treated as
proof that a size is honest, since anyone crafting a file can compute them.
Forward scanning after damage makes one pass with one buffer per segment, however
many false markers a file holds. A dataset over the index limit is an error rather
than a silently replayed prefix.

## Recovery

Nothing is skipped silently. Each case below increments a counter in
`Integrity`, and any non-zero counter makes the dataset incomplete.

| Damage | Behavior |
|---|---|
| Payload CRC, decompression or length mismatch | Skip the record, continue at the next frame |
| Frame header CRC or sync mismatch | Scan forward for the next sync marker, continue there |
| Record fails validation or has unknown fields | Skip the record |
| Frame runs past end of file | Treat as a partial tail, keep earlier records |
| Footer missing | Segment is unsealed |
| Footer count differs from frames seen | Count mismatch |
| Segment header unreadable | Skip the segment |
| Same run and index seen twice | Ignore the second segment |
| Same run and sequence seen twice | Ignore the second record |
| Gap in a run's segment indexes | Missing segments |
| Run has no `final` footer | Incomplete run |

These stop the read with an error:

- Unknown format version or schema version.
- A directory with no segments.
- More records than the index limit.

The sync marker is random per segment and stored only in that segment, so
content inside a record can't forge a frame boundary during a forward scan.

## Writing

Each frame is one `write` call. If a write fails partway, the writer truncates
back to the last good frame. If that fails too, it abandons the segment unsealed
and starts a new one on the next append, which readers report.

Unsealed data lives in the OS page cache until a sync, so a machine crash can
lose recent records. Those losses show up as a partial tail or an unsealed
segment, not as a clean dataset.

## Compatibility

Any change in meaning needs a new version. Readers reject versions they don't
know, and record decoding rejects unknown fields, so an old reader can't quietly
misinterpret a newer file.
