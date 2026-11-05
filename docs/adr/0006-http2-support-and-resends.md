# ADR 0006: Standard library HTTP/2, with client resends counted

Status: accepted

## Context

v1 needs real HTTP/2, on both sides of the proxy and in replay. Replay also promises not to
make invisible extra calls. Disabling connection reuse removed that risk on HTTP/1.1, but
it doesn't carry over to HTTP/2.

Probing Go's client with a server speaking raw frames showed it resends after
`REFUSED_STREAM` and after a `GOAWAY` that excludes the stream, even on a single-use
connection. There is no setting to prevent this.

## Decision

- Use `net/http` with `http.Protocols` for all HTTP/2, with no extra dependency.
- Make h2c an explicit choice that excludes HTTP/1.1, so a fallback fails instead of
  producing HTTP/1.1 results labeled as HTTP/2.
- Count each write of a request with `httptrace`, and report it as `attempts` per call and
  `resends` per target.
- Don't treat a resend as incomplete evidence. The server has stated the request wasn't
  processed, and the call still produced one result. It is reported as a warning.

## Alternatives considered

**Giving requests a non-rewindable body to block resends.** The client refuses to resend
such a request once its body has been written. An empty body would then go out as a stream
with a DATA frame, so a target would see a different request than the one recorded.

**Writing an HTTP/2 client with no resend logic.** That's a lot of code to own, for a case
that's already safe under the protocol's rules and now visible.

**Failing the run on any resend.** A server under load can legitimately refuse streams, and
that would make runs fail for reasons unrelated to the candidate.

## Consequences

- The promise is now "one attempt by replaydiff, and any resend by the HTTP client is
  counted", which is weaker than the promise for HTTP/1.1, and accurate.
- A server that refuses a stream and processes it anyway could see a duplicate. The count
  shows that a resend happened, not whether the server honored the protocol.
- Tests depend on how a specific Go version behaves, so they may need attention on upgrades.
- Each HTTP/2 call still opens a connection, which loses multiplexing. The cost hasn't been
  measured. Reuse could be restored for HTTP/2 alone if measurements justify it, since
  resends are counted either way, while HTTP/1.1's must stay prevented.
