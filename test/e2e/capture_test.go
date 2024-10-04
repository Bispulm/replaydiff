package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const e2ePolicy = `
query_params: [token]
json_paths: ["$.customer.email", "$.access_token", "$.password", "$.user.email"]
session:
  sources: ["cookie:sid"]
`

func newSentinel(t *testing.T) string {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "rdsentinel" + hex.EncodeToString(b[:])
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// assertAbsent scans bytes for the sentinels, including encodings a stored form
// could use, and names the artifact that held one.
func assertAbsent(t *testing.T, artifact string, data []byte, sentinels ...string) {
	t.Helper()
	for _, secret := range sentinels {
		hit := bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte(url.QueryEscape(secret)))
		for pad := range 3 {
			encoded := base64.StdEncoding.EncodeToString(append(make([]byte, pad), secret...))
			hit = hit || bytes.Contains(data, []byte(encoded[(pad*8+5)/6:len(encoded)-4]))
		}
		if hit {
			t.Errorf("sentinel found in %s", artifact)
		}
	}
}

// scanDir checks every file under dir, which also catches temporary files.
func scanDir(t *testing.T, dir string, sentinels ...string) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		count++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		assertAbsent(t, path, data, sentinels...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

type result struct {
	code   int
	stdout []byte
	stderr []byte
}

func runCommand(t *testing.T, env []string, name string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary(t, name), args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError) //nolint:errorlint // Run returns it unwrapped.
		if !ok {
			t.Fatalf("%s: %v", name, err)
		}
		code = exitErr.ExitCode()
	}
	return result{code: code, stdout: stdout.Bytes(), stderr: stderr.Bytes()}
}

func TestCaptureStoresRedactedRecordsAndForwardsRealValues(t *testing.T) {
	work := t.TempDir()
	trafficDir := filepath.Join(work, "traffic")
	policy := writeFile(t, filepath.Join(work, "redact.yaml"), e2ePolicy)

	authSecret, cookieSecret, apiKeySecret := newSentinel(t), newSentinel(t), newSentinel(t)
	querySecret, bodySecret, malformedSecret := newSentinel(t), newSentinel(t), newSentinel(t)
	all := []string{authSecret, cookieSecret, apiKeySecret, querySecret, bodySecret, malformedSecret}

	service := start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", "baseline", "--instance", "a")
	serviceURL := service.baseURL(t)
	proxy := start(t, nil, "replaydiff", "capture",
		"--listen", "127.0.0.1:0", "--upstream", serviceURL, "--out", trafficDir, "--redact", policy, "--log-level", "debug")
	proxyURL := proxy.baseURL(t)

	status, body := httpGet(t, proxyURL+"/v1/orders/ord-1?token="+querySecret, map[string]string{
		"Authorization": "Bearer " + authSecret,
		"Cookie":        "sid=" + cookieSecret,
		"X-Api-Key":     apiKeySecret,
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	// Live responses keep the values that stored records must not.
	if !strings.Contains(body, "1@customers.example.test") {
		t.Fatalf("live response was altered: %s", body)
	}
	if status, _ := httpGet(t, proxyURL+"/v1/compressed", map[string]string{"Accept-Encoding": "gzip"}); status != http.StatusOK {
		t.Fatalf("compressed status = %d", status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, payload := range []string{
		fmt.Sprintf(`{"username":"u1","password":%q}`, bodySecret),
		`{"username":"u1","password":"` + malformedSecret,
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/v1/login", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if err := proxy.stop(t); err != nil {
		t.Fatalf("capture exit: %v\nlogs:\n%s", err, proxy.output())
	}

	if n := scanDir(t, trafficDir, all...); n == 0 {
		t.Fatal("no traffic files written")
	}
	assertAbsent(t, "capture logs", []byte(proxy.output()), all...)

	inspected := runCommand(t, nil, "replaydiff", "inspect", "--traffic", trafficDir)
	if inspected.code != 0 {
		t.Fatalf("inspect exit %d: %s", inspected.code, inspected.stderr)
	}
	assertAbsent(t, "inspect output", inspected.stdout, all...)

	var records []map[string]any
	dec := json.NewDecoder(bytes.NewReader(inspected.stdout))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		records = append(records, rec)
	}
	if len(records) != 4 {
		t.Fatalf("records = %d, want 4:\n%s", len(records), inspected.stdout)
	}
	first := records[0]["request"].(map[string]any)
	if first["raw_query"] != "token=REDACTED" {
		t.Fatalf("query = %v", first["raw_query"])
	}
	if records[0]["session_key"] == "" || records[0]["session_key"] == nil {
		t.Fatalf("session key missing: %v", records[0])
	}
	malformed := records[3]
	if body := malformed["request"].(map[string]any)["body"].(map[string]any); body["state"] != "omitted" || body["reason"] != "malformed_json" {
		t.Fatalf("malformed request body = %v", body)
	}
	if malformed["replay"].(map[string]any)["eligible"] != false {
		t.Fatalf("malformed record must not be replayable: %v", malformed["replay"])
	}
}

func TestCaptureRefusesToRunWithoutARedactionPolicy(t *testing.T) {
	got := runCommand(t, nil, "replaydiff", "capture", "--upstream", "http://127.0.0.1:1", "--out", t.TempDir())
	if got.code != 2 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if !strings.Contains(string(got.stderr), "--redact") {
		t.Fatalf("stderr = %s", got.stderr)
	}
}
