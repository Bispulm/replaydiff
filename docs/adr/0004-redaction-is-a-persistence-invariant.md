# ADR 0004: Redaction is a persistence invariant that fails closed

Status: accepted

## Context

A recording that holds a credential is a security incident waiting to be shared.
The usual failure isn't a missing rule. It's a fallback path: a body that couldn't
be parsed gets stored as it was, because keeping it seemed more useful.

## Decision

- Redaction runs in-process before encoding. The writer only accepts encoded
  records, so raw data has no route to storage.
- Mandatory header rules always apply and can't be configured away.
- Bodies are stored only if parsed and re-encoded, or explicitly listed as opaque.
- Anything else is omitted with a fixed reason code. There is no raw fallback.
- Parser errors are discarded rather than logged, since they can quote content.
- Rule hits record the configured rule, never keys or values from traffic.
- Unknown policy keys are errors, and rules that can't be applied yet are refused.

## Alternatives considered

**Patching matched values in the original bytes.** This keeps formatting, but the
bytes that a rule looked at and the bytes that a service reads can differ when keys
are duplicated or escaped. Storing the parsed tree removes that gap.

**Failing the capture when a body can't be sanitized.** This would affect live
traffic, or lose the whole record. Omitting just the body keeps the metadata.

**Entropy or pattern scanning for secrets.** Useful as a later addition, but it
would imply a guarantee it can't provide. The documented rule set is honest about
what it protects.

## Consequences

- Traffic with unsupported content types is reduced to metadata unless opted in.
- Redacted requests may behave differently on replay. This is documented, and
  per-target credentials exist to reduce it.
- Stored JSON isn't byte-identical to the original.
- Tests plant unique sentinels in every covered location and scan the results,
  including base64 and percent-encoded forms.
