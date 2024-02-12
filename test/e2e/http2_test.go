package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCert writes a throwaway self-signed certificate for 127.0.0.1.
func testCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "replaydiff e2e"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeFile(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	return certFile, keyFile
}

// h2Client is a client that can only speak HTTP/2, so a fallback fails.
func h2Client(t *testing.T, caFile string) *http.Transport {
	t.Helper()
	protocols := new(http.Protocols)
	transport := &http.Transport{Protocols: protocols}
	if caFile == "" {
		protocols.SetUnencryptedHTTP2(true)
	} else {
		protocols.SetHTTP2(true)
		data, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			t.Fatal("no certificates in CA file")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func h2Get(t *testing.T, client *http.Transport, url string, header map[string]string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Fatalf("client spoke HTTP/%d", resp.ProtoMajor)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

type h2Report struct {
	EvidenceComplete bool `json:"evidence_complete"`
	Summary          struct {
		Replayed int `json:"replayed"`
		Targets  map[string]struct {
			Protocols map[string]int `json:"protocols"`
		} `json:"targets"`
	} `json:"summary"`
	Samples []struct {
		Calls [3]struct {
			Proto string `json:"proto"`
		} `json:"calls"`
	} `json:"samples"`
}

func runHTTP2Path(t *testing.T, serviceFlags, proxyFlags, runFlags []string, scheme, caFile string) {
	t.Helper()
	work := t.TempDir()
	trafficDir := filepath.Join(work, "traffic")
	policy := writeFile(t, filepath.Join(work, "redact.yaml"), e2ePolicy)
	fixture := func(variant, instance string) string {
		args := append([]string{"--listen", "127.0.0.1:0", "--variant", variant, "--instance", instance}, serviceFlags...)
		p := start(t, nil, "replaydiff-fixture", args...)
		return strings.Replace(p.baseURL(t), "http://", scheme+"://", 1)
	}
	service := fixture("baseline", "capture")
	a, b, c := fixture("baseline", "a"), fixture("baseline", "b"), fixture("candidate", "c")

	args := append([]string{"capture", "--listen", "127.0.0.1:0", "--upstream", service, "--out", trafficDir, "--redact", policy, "--log-level", "debug"}, proxyFlags...)
	proxy := start(t, nil, "replaydiff", args...)
	proxyURL := strings.Replace(proxy.baseURL(t), "http://", scheme+"://", 1)

	client := h2Client(t, caFile)
	secret := newSentinel(t)

	// The fixture reports the protocol it saw, so this proves the upstream hop.
	if body := h2Get(t, client, proxyURL+"/v1/protocol", nil); !strings.Contains(body, "HTTP/2.0") {
		t.Fatalf("upstream hop wasn't HTTP/2: %s", body)
	}
	body := h2Get(t, client, proxyURL+"/v1/orders/ord-1?token="+secret, map[string]string{
		"Authorization": "Bearer " + secret,
		"Cookie":        "sid=" + secret,
	})
	if !strings.Contains(body, "@customers.example.test") {
		t.Fatalf("live response was altered: %s", body)
	}
	if err := proxy.stop(t); err != nil {
		t.Fatalf("capture exit: %v\n%s", err, proxy.output())
	}

	scanDir(t, trafficDir, secret)
	assertAbsent(t, "capture logs", []byte(proxy.output()), secret)
	inspected := runCommand(t, nil, "replaydiff", "inspect", "--traffic", trafficDir)
	if inspected.code != 0 {
		t.Fatalf("inspect exit %d: %s", inspected.code, inspected.stderr)
	}
	assertAbsent(t, "inspect output", inspected.stdout, secret)
	for _, line := range strings.Split(strings.TrimSpace(string(inspected.stdout)), "\n") {
		var rec struct {
			Protocol string `json:"protocol"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Protocol != "h2" {
			t.Fatalf("record protocol = %q", rec.Protocol)
		}
	}

	report := filepath.Join(work, "report.json")
	runArgs := append([]string{
		"run", "--traffic", trafficDir, "--report", report, "--redact", policy, "--rps", "0",
		"--baseline-a", a, "--baseline-b", b, "--candidate", c,
		"--allow-origin", a, "--allow-origin", b, "--allow-origin", c,
	}, runFlags...)
	run := runCommand(t, nil, "replaydiff", runArgs...)
	if run.code != 0 {
		t.Fatalf("run exit %d\n%s\n%s", run.code, run.stdout, run.stderr)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, "report", data, secret)
	var parsed h2Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.EvidenceComplete || parsed.Summary.Replayed != 2 {
		t.Fatalf("report = %s", data)
	}
	for role, target := range parsed.Summary.Targets {
		if target.Protocols["HTTP/2.0"] != 2 || len(target.Protocols) != 1 {
			t.Fatalf("%s protocols = %v", role, target.Protocols)
		}
	}
	for _, sample := range parsed.Samples {
		for _, call := range sample.Calls {
			if call.Proto != "HTTP/2.0" {
				t.Fatalf("call proto = %q", call.Proto)
			}
		}
	}
}

func TestHTTP2OverCleartextEndToEnd(t *testing.T) {
	runHTTP2Path(t, []string{"--h2c"}, []string{"--h2c", "--upstream-h2c"}, []string{"--target-h2c"}, "http", "")
}

func TestHTTP2OverTLSEndToEnd(t *testing.T) {
	certFile, keyFile := testCert(t, t.TempDir())
	tlsFlags := []string{"--tls-cert", certFile, "--tls-key", keyFile}
	runHTTP2Path(t, tlsFlags,
		append([]string{"--upstream-ca-file", certFile}, tlsFlags...),
		[]string{"--target-ca-file", certFile},
		"https", certFile)
}

func TestUntrustedTargetCertificateCannotPass(t *testing.T) {
	work := t.TempDir()
	certFile, keyFile := testCert(t, work)
	trafficDir := filepath.Join(work, "traffic")
	policy := writeFile(t, filepath.Join(work, "redact.yaml"), e2ePolicy)
	plain := start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--instance", "capture")
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0", "--upstream", plain.baseURL(t), "--out", trafficDir, "--redact", policy)
	httpGet(t, proxy.baseURL(t)+"/v1/catalog", nil)
	if err := proxy.stop(t); err != nil {
		t.Fatal(err)
	}
	secure := func(instance string) string {
		p := start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--instance", instance, "--tls-cert", certFile, "--tls-key", keyFile)
		return strings.Replace(p.baseURL(t), "http://", "https://", 1)
	}
	a, b, c := secure("a"), secure("b"), secure("c")
	got := runCommand(t, nil, "replaydiff", "run", "--traffic", trafficDir, "--report", filepath.Join(work, "report.json"), "--redact", policy,
		"--baseline-a", a, "--baseline-b", b, "--candidate", c, "--allow-origin", a, "--allow-origin", b, "--allow-origin", c)
	if got.code != 2 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
}
