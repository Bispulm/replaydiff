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

const fixtureDescriptors = "../fixture/proto/orders.binpb"

func TestCaptureRejectsInvalidInvocations(t *testing.T) {
	policy := writePolicy(t, "")
	protoPolicy := writePolicy(t, "proto_fields: [fixture.orders.v1.Customer.email]")
	dir := t.TempDir()
	valid := []string{"--upstream", "http://127.0.0.1:1", "--out", dir, "--redact", policy}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no upstream":         {[]string{"--out", dir, "--redact", policy}, "--upstream"},
		"no output":           {[]string{"--upstream", "http://127.0.0.1:1", "--redact", policy}, "--out"},
		"no policy":           {[]string{"--upstream", "http://127.0.0.1:1", "--out", dir}, "--redact"},
		"bad scheme":          {[]string{"--upstream", "ftp://127.0.0.1:1", "--out", dir, "--redact", policy}, "http or https"},
		"userinfo in url":     {[]string{"--upstream", "http://user:hunter2@127.0.0.1:1", "--out", dir, "--redact", policy}, "credentials"},
		"query in url":        {[]string{"--upstream", "http://127.0.0.1:1/?a=1", "--out", dir, "--redact", policy}, "query"},
		"missing policy":      {[]string{"--upstream", "http://127.0.0.1:1", "--out", dir, "--redact", policy + ".absent"}, "policy"},
		"unknown flag":        {append([]string{"--nope"}, valid...), "-nope"},
		"bad size":            {append([]string{"--max-request-body", "lots"}, valid...), "max-request-body"},
		"bad log level":       {append([]string{"--log-level", "loud"}, valid...), "log-level"},
		"negative queue":      {append([]string{"--queue", "-1"}, valid...), "negative"},
		"cert without key":    {append([]string{"--tls-cert", policy}, valid...), "--tls-key"},
		"key without cert":    {append([]string{"--tls-key", policy}, valid...), "--tls-cert"},
		"h2c and tls":         {append([]string{"--h2c", "--tls-cert", policy, "--tls-key", policy}, valid...), "--h2c"},
		"missing ca file":     {append([]string{"--upstream-ca-file", policy + ".absent"}, valid...), "--upstream-ca-file"},
		"ca file not pem":     {append([]string{"--upstream-ca-file", policy}, valid...), "--upstream-ca-file"},
		"h2c upstream tls":    {[]string{"--upstream", "https://127.0.0.1:1", "--upstream-h2c", "--out", dir, "--redact", policy}, "h2c"},
		"negative workers":    {append([]string{"--workers", "-1"}, valid...), "negative"},
		"unset secret env":    {append([]string{"--session-secret-env", "REPLAYDIFF_TEST_UNSET_VARIABLE"}, valid...), "REPLAYDIFF_TEST_UNSET_VARIABLE"},
		"missing descriptors": {append([]string{"--descriptor-set", policy + ".absent"}, valid...), "descriptor set"},
		"not descriptors":     {append([]string{"--descriptor-set", writePolicy(t, "not protobuf")}, valid...), "descriptor set"},
		"proto rule, no set":  {[]string{"--upstream", "http://127.0.0.1:1", "--out", dir, "--redact", protoPolicy}, "--descriptor-set"},
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

// The descriptor set reaches redaction, so a policy with protobuf rules is accepted and
// capture goes on to fail only on the address it can't listen on.
func TestCaptureInterpretsGRPCWithADescriptorSet(t *testing.T) {
	policy := writePolicy(t, "proto_fields: [fixture.orders.v1.Customer.email]")
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"capture", "--upstream", "http://127.0.0.1:1", "--out", t.TempDir(), "--redact", policy,
		"--descriptor-set", fixtureDescriptors, "--listen", "127.0.0.1:-1"}, &out, &errOut)
	if code != ExitFailure || strings.Contains(errOut.String(), "proto_fields") || !strings.Contains(errOut.String(), "listen") {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
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
