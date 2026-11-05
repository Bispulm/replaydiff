# ADR 0002: Use the standard library for the CLI

Status: accepted

## Context

The CLI has a few subcommands, and its exit codes are a stable CI contract.

## Decision

Dispatch subcommands by hand and parse flags with the standard `flag` package.

## Consequences

- There's no framework dependency, and `cli.Run` is a plain function that tests
  can call with arguments and buffers.
- Every exit path is explicit, so a framework default can't turn a failure into
  a success.
- There's no generated shell completion. This can be revisited if the command
  surface grows.
