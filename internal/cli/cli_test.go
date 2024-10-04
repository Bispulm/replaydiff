package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestNoArgumentsIsAUsageFailure(t *testing.T) {
	code, _, stderr := run(t)
	if code != ExitFailure {
		t.Fatalf("exit code = %d, want %d", code, ExitFailure)
	}
	for _, want := range []string{"capture", "run", "report"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("usage does not mention %q:\n%s", want, stderr)
		}
	}
}

func TestUnknownCommandIsAFailureNotASuccess(t *testing.T) {
	code, _, stderr := run(t, "nope")
	if code != ExitFailure {
		t.Fatalf("exit code = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr, `unknown command "nope"`) {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestHelpSucceedsAndPrintsToStdout(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, stdout, _ := run(t, arg)
		if code != ExitOK {
			t.Errorf("%s: exit code = %d, want %d", arg, code, ExitOK)
		}
		if !strings.Contains(stdout, "capture") {
			t.Errorf("%s: stdout = %q", arg, stdout)
		}
	}
}

func TestVersionPrintsBuildVersion(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.HasPrefix(stdout, "replaydiff ") {
		t.Errorf("stdout = %q", stdout)
	}
}
