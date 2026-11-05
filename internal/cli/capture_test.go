package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseByteSize(t *testing.T) {
	// Repeated because every suffix ends in B: suffix matching must not depend
	// on the order it happens to try them in.
	for range 200 {
		for in, want := range map[string]int64{"10": 10, "1KiB": 1024, "2MiB": 2 << 20, "1GiB": 1 << 30, "5B": 5} {
			got, err := parseByteSize(in)
			if err != nil || got != want {
				t.Fatalf("parseByteSize(%q) = %d, %v, want %d", in, got, err, want)
			}
		}
	}
	for _, in := range []string{"", "abc", "-1", "1XB", "0", "99999999999GiB"} {
		if _, err := parseByteSize(in); err == nil {
			t.Errorf("parseByteSize(%q): want error", in)
		}
	}
}

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "redact.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCaptureRejectsInvalidInvocations(t *testing.T) {
	policy := writePolicy(t, "")
	dir := t.TempDir()
	valid := []string{"--upstream", "http://127.0.0.1:1", "--out", dir, "--redact", policy}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no upstream":      {[]string{"--out", dir, "--redact", policy}, "--upstream"},
		"no output":        {[]string{"--upstream", "http://127.0.0.1:1", "--redact", policy}, "--out"},
		"no policy":        {[]string{"--upstream", "http://127.0.0.1:1", "--out", dir}, "--redact"},
		"bad scheme":       {[]string{"--upstream", "ftp://127.0.0.1:1", "--out", dir, "--redact", policy}, "http or https"},
		"userinfo in url":  {[]string{"--upstream", "http://user:hunter2@127.0.0.1:1", "--out", dir, "--redact", policy}, "credentials"},
		"query in url":     {[]string{"--upstream", "http://127.0.0.1:1/?a=1", "--out", dir, "--redact", policy}, "query"},
		"missing policy":   {[]string{"--upstream", "http://127.0.0.1:1", "--out", dir, "--redact", policy + ".absent"}, "policy"},
		"unknown flag":     {append([]string{"--nope"}, valid...), "-nope"},
		"bad size":         {append([]string{"--max-request-body", "lots"}, valid...), "max-request-body"},
		"bad log level":    {append([]string{"--log-level", "loud"}, valid...), "log-level"},
		"unset secret env": {append([]string{"--session-secret-env", "REPLAYDIFF_TEST_UNSET_VARIABLE"}, valid...), "REPLAYDIFF_TEST_UNSET_VARIABLE"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), append([]string{"capture"}, tc.args...), &out, &errOut)
			if code != ExitFailure {
				t.Fatalf("exit code = %d, want %d", code, ExitFailure)
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("stderr = %q, want it to mention %q", errOut.String(), tc.want)
			}
			if strings.Contains(errOut.String(), "hunter2") {
				t.Fatalf("error echoes a credential: %q", errOut.String())
			}
		})
	}
}

func TestInspectFailsOnMissingAndEmptyTraffic(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"inspect"}, &out, &errOut); code != ExitFailure {
		t.Fatalf("no flags: exit code = %d", code)
	}
	if code := Run(context.Background(), []string{"inspect", "--traffic", t.TempDir()}, &out, &errOut); code != ExitFailure {
		t.Fatalf("empty dir: exit code = %d", code)
	}
}
