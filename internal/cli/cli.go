// Package cli implements the replaydiff command line interface.
package cli

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"
)

// Process exit codes. These are part of the CI contract documented in the
// README: scripts branch on them, so their meanings must stay stable.
const (
	// ExitOK means the command completed and, for gating commands, the
	// configured policy was met.
	ExitOK = 0
	// ExitRegression means a regression exceeding the configured policy was
	// detected.
	ExitRegression = 1
	// ExitFailure means invalid configuration, an execution failure, or
	// materially incomplete evidence. It is never a pass.
	ExitFailure = 2
)

// Version is overridden at link time for release builds.
var Version = ""

const usage = `replaydiff captures HTTP traffic, replays it against two baselines and a
candidate, and reports behavior changes.

Usage:
  replaydiff <command> [flags]

Commands:
  capture   Proxy traffic and store redacted recordings
  run       Replay recordings against baseline A, baseline B and a candidate
  report    Render results and apply the CI policy
  inspect   Print stored records for review
  version   Print the build version
  help      Print this message

Exit codes:
  0  completed and met the configured policy
  1  a regression exceeded the configured policy
  2  invalid configuration, execution failure, or incomplete evidence
`

// Run executes the command named by args and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitFailure
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	case "version":
		fmt.Fprintf(stdout, "replaydiff %s\n", buildVersion())
		return ExitOK
	case "capture":
		return runCapture(ctx, args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "run", "report":
		fmt.Fprintf(stderr, "replaydiff %s: not implemented\n", args[0])
		return ExitFailure
	default:
		fmt.Fprintf(stderr, "replaydiff: unknown command %q\n\n%s", args[0], usage)
		return ExitFailure
	}
}

func buildVersion() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}
