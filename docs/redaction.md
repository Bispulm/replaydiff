# Redaction

Redaction runs in the capture process, in memory, before a record is encoded.
Sanitized data is the only thing the writer ever receives.

**This is rule-based. It does not detect unknown secrets.** It protects the
locations listed here, and anything else in a stored body or header is kept. If
a service puts a secret somewhere these rules don't reach, it will be stored.
Review a sample of your recordings with `replaydiff inspect` before sharing them.

## Always on

These can't be turned off:

| Rule | Applies to |
|---|---|
| `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization` | Request and response headers and trailers, any case |
| Any header name containing `auth`, `token`, `secret`, `password`, `passwd`, `credential`, `session`, `cookie`, `api-key`, `apikey` or `api_key` | Same |

The name match over-redacts on purpose. For example, `X-Author` is redacted too.

These are never stored:

- **Hop-by-hop headers**, including any named by `Connection`.
- **Headers describing the original bytes:** `Content-Length`, `Content-Encoding`,
  `Content-MD5`, `Digest`, `Content-Digest`, `Repr-Digest` and `ETag`. A stored
  digest could be used to confirm a guess at a redacted value.

## Policy file

`capture` requires `--redact FILE`, even if the file is empty, because bodies are
stored according to its rules.

```yaml
headers: [X-Internal-Id]
query_params: [token, password]
json_paths: ["$.user.email", "$.items[*].card", "$..password"]
opaque_content_types: [text/plain]
proto_fields: [fixture.orders.v1.Customer.email]
session:
  sources: ["cookie:sid", "header:X-Session-Id", "query:session"]
```

Unknown keys are errors, because ignoring a misspelled rule would silently leave
data unprotected.

## Query parameters

`query_params` apply to the request query, form-encoded bodies, and the query and
fragment of `Referer`, `Location` and `Content-Location`. Names match after
percent-decoding, regardless of case.

| Case | Result |
|---|---|
| Listed name | Value replaced with `REDACTED` |
| Listed name inside a decoded value or name, such as `redirect=%2Fcb%3Ftoken%3Dx` or `#/cb?token=x` | Pair masked |
| A name merely ending in a listed name, such as `mytoken=x` for rule `token` | Pair masked |
| Malformed percent-encoding in a value | Value replaced |
| A name that can't be decoded, or holds a listed name followed by `=` once decoded | Name and value both replaced |
| Unparsable URL header | Whole value replaced |
| `Link` header containing `?` | Whole value replaced |

## JSON paths

Rules apply to request and response bodies whose media type is
`application/json` or ends in `+json`.

| Syntax | Matches |
|---|---|
| `$` | The whole document |
| `.name` | A member. Names may use letters, digits, `_` and `-`. |
| `['any name']` | A member with any other characters |
| `[3]` | An array element |
| `.*` or `[*]` | All members or elements |
| `..name` or `..['any name']` | A member at any depth |

Filters, slices, negative indexes, unions and `$..*` are not supported, and are
rejected at startup rather than ignored.

Member names match regardless of case, because many decoders accept any case.
A matched value is replaced with `"[REDACTED]"`, whatever its type, including a
whole object.

Bodies are parsed and re-encoded rather than patched, which has these effects:

- A duplicate key keeps only its last value, so an earlier one is never stored.
- Escaped names such as `email` are matched.
- Numbers keep their exact text, so precision isn't lost.
- Object key order and insignificant whitespace aren't preserved.

## Protobuf fields

`proto_fields` names fields of gRPC messages by their full name in the descriptor set given
with `--descriptor-set`:

```yaml
proto_fields:
  - fixture.orders.v1.Customer.email
  - fixture.orders.v1.GetOrderRequest.auth_token
```

A rule follows its message type, not a path. It applies wherever that message appears, in
requests and responses: at any depth, in lists, in map values, and inside a
`google.protobuf.Any` whose type the set has. Each `Any` is decoded separately, so they are
unpacked at most 8 deep, and a message nesting them deeper is omitted.

| Field | Result |
|---|---|
| `string` or `bytes` | Replaced with `[REDACTED]` |
| Any other scalar, an enum or a message | Cleared |
| Repeated or map | Emptied |

A field the set doesn't have is refused at startup, and so is `proto_fields` without
`--descriptor-set`, because a rule that matches nothing would protect nothing.

Messages are decoded and encoded again, deterministically. A message is never stored as it
arrived:

| Condition | Reason | Replayable if it's the request |
|---|---|---|
| No descriptor set, or a method it doesn't have | `proto_descriptor_missing`, `proto_method_unknown` | No |
| More than one message, or a streaming method | `grpc_streaming` | No |
| Incomplete framing, or the compressed flag with no encoding | `grpc_malformed_frame` | No |
| Bytes that don't decode as the message | `proto_malformed` | No |
| Fields the set doesn't describe | `proto_unknown_fields` | No |
| An `Any` of a type outside the set | `proto_any_unresolved` | No |
| `Any` messages packed more than 8 deep | `proto_any_too_deep` | No |

Unknown fields and foreign `Any` values are bytes that no rule can see into, so the whole
message is omitted rather than stored with them. An omitted response keeps its request
replayable, as for other bodies.

gRPC metadata goes through the header rules. `grpc-message`, which servers fill with whatever
went wrong, and binary metadata such as `grpc-status-details-bin` are always replaced, because
no rule can check what they hold.

## What happens when a body can't be sanitized

Nothing is stored, and there is no fallback to the original bytes.

| Condition | Body state | Reason | Replayable |
|---|---|---|---|
| Malformed JSON, or data after the JSON value | `omitted` | `malformed_json` | No |
| Corrupt compressed data | `omitted` | `malformed_compression` | No |
| `br`, or stacked encodings | `omitted` | `unsupported_encoding` | No |
| Decompressed size over the limit (8 MiB by default) | `omitted` | `decompressed_too_large` | No |
| More than one `Content-Type`, which servers resolve differently | `omitted` | `ambiguous_content_type` | No |
| Request media type with no rules | `omitted` | `unsupported_content_type` | No |
| Response media type with no rules | `omitted` | `unsupported_content_type` | Yes |

gzip, deflate and zstd are decompressed with a size limit. Stored bodies are
always decompressed.

An unsupported response type keeps its request replayable, since the replay
compares fresh responses from the targets and doesn't use the stored one. Other
media types are stored only if listed in `opaque_content_types`, which means
rules can't protect them.

## Sessions

If a session source matches, the record stores
`HMAC-SHA256(secret, source, value)`, truncated to 128 bits, and never the value.

| `--session-secret-env` | Scope of correlation |
|---|---|
| Not set | A random secret per capture process. Sessions correlate only within that run. |
| Set | Any capture using the same secret. Use this to correlate across replicas. Rotate it to end correlation. |

The secret is never written to a recording. Anyone holding it could test a guessed
session value against the digests, so treat it as a credential.

## Confidentiality and replay fidelity

Redacting a value can change how a service behaves. A request whose credential
was removed may now get a 401, and a redacted ID may no longer resolve.

- Redacted headers are not sent during replay. The placeholder is never used as a
  credential.
- Per-target credentials can be supplied from environment variables at replay
  time. They are never recovered from recordings.
- A redacted JSON field in a request is sent as `"[REDACTED]"`, which every target
  sees equally.

## Known limits

- Secrets in URL paths, such as `/reset/abc123`, are not covered.
- Secrets in header names, JSON object keys or protobuf map keys are not covered.
- Secrets inside a string that holds encoded JSON or base64 are not covered.
- Query and form rules don't look inside bodies of other types.
- Opaque content types are stored as they are.
- Values in process memory are not protected from someone who can read that memory.
