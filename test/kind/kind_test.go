// Package kind tests capture and replay through the Helm deployment on a kind cluster.
// It needs Docker, kind, kubectl and helm, and runs only with REPLAYDIFF_KIND=1.
//
// The cluster has its own kubeconfig file, so the shared default context is never
// switched. Set REPLAYDIFF_KIND_KEEP=1 to keep the cluster for another run, and
// REPLAYDIFF_K8S_LOCK to a directory path to serialize with other heavy workloads.
package kind

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"
)

const (
	clusterName = "replaydiff-dev"
	namespace   = "replaydiff"
	image       = "replaydiff:kind-e2e"
	release     = "orders"
	repoRoot    = "../.."
)

type env struct {
	t          *testing.T
	kubeconfig string
}

// command runs a tool with its own deadline. It doesn't use the test's context, which is
// canceled before cleanups run, and cleanups delete the cluster.
func command(t *testing.T, timeout time.Duration, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func must(t *testing.T, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	out, err := command(t, timeout, name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func (e *env) kubectl(args ...string) (string, error) {
	e.t.Helper()
	return command(e.t, 5*time.Minute, "kubectl", append([]string{"--kubeconfig", e.kubeconfig, "--namespace", namespace}, args...)...)
}

func (e *env) mustKubectl(args ...string) string {
	e.t.Helper()
	out, err := e.kubectl(args...)
	if err != nil {
		e.t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// lock serializes with other heavy workloads on the machine, if a lock path is set.
func lock(t *testing.T) {
	t.Helper()
	path := os.Getenv("REPLAYDIFF_K8S_LOCK")
	if path == "" {
		return
	}
	deadline := time.Now().Add(30 * time.Minute)
	for {
		if err := os.Mkdir(path, 0o755); err == nil {
			break
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is still held", path)
		}
		t.Logf("waiting for %s", path)
		time.Sleep(15 * time.Second)
	}
	note := fmt.Sprintf("owner: replaydiff\npurpose: kind end-to-end test\nstarted: %s\n", time.Now().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(path, "note"), []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
}

// cluster creates replaydiff-dev with its own kubeconfig, or reuses one left running.
func cluster(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, kubeconfig: filepath.Join(t.TempDir(), "kubeconfig")}
	clusters := must(t, time.Minute, "kind", "get", "clusters")
	if !strings.Contains("\n"+clusters, "\n"+clusterName+"\n") {
		must(t, 5*time.Minute, "kind", "create", "cluster", "--name", clusterName, "--kubeconfig", e.kubeconfig, "--wait", "3m")
	} else {
		config := must(t, time.Minute, "kind", "get", "kubeconfig", "--name", clusterName)
		if err := os.WriteFile(e.kubeconfig, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("REPLAYDIFF_KIND_KEEP") != "1" {
		t.Cleanup(func() {
			if out, err := command(t, 3*time.Minute, "kind", "delete", "cluster", "--name", clusterName, "--kubeconfig", e.kubeconfig); err != nil {
				t.Errorf("deleting the cluster: %v\n%s", err, out)
			}
		})
	}
	return e
}

func newSentinel(t *testing.T) string {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "rdsentinel" + hex.EncodeToString(b[:])
}

func (e *env) apply(templatePath string, data any) {
	e.t.Helper()
	text, err := os.ReadFile(templatePath)
	if err != nil {
		e.t.Fatal(err)
	}
	var manifest bytes.Buffer
	if err := template.Must(template.New("m").Parse(string(text))).Execute(&manifest, data); err != nil {
		e.t.Fatal(err)
	}
	path := filepath.Join(e.t.TempDir(), filepath.Base(templatePath))
	if err := os.WriteFile(path, manifest.Bytes(), 0o600); err != nil {
		e.t.Fatal(err)
	}
	e.mustKubectl("apply", "-f", path)
}

var forwarding = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

// portForward forwards a local port to a Service port and returns its URL.
func (e *env) portForward(service string, port int) string {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", e.kubeconfig, "--namespace", namespace,
		"port-forward", "service/"+service, ":"+strconv.Itoa(port))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	found := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if m := forwarding.FindStringSubmatch(scanner.Text()); m != nil {
				found <- m[1]
			}
		}
		// The forward ends when the test does, and a read error only means the same.
		_ = scanner.Err()
	}()
	select {
	case local := <-found:
		return "http://127.0.0.1:" + local
	case <-time.After(30 * time.Second):
		e.t.Fatalf("no port forward to %s:%d", service, port)
		return ""
	}
}

func get(t *testing.T, url string, header map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// TestCaptureAndReplayThroughTheDeployment installs the chart with the fixture behind
// capture, sends traffic through the Service, and replays the recording from inside the
// cluster against two baselines and a candidate. The CI gate must find the candidate's
// regressions, and a credential sent with the traffic must appear in no recording.
func TestCaptureAndReplayThroughTheDeployment(t *testing.T) {
	if os.Getenv("REPLAYDIFF_KIND") != "1" {
		t.Skip("set REPLAYDIFF_KIND=1 to run against a kind cluster")
	}
	for _, tool := range []string{"docker", "kind", "kubectl", "helm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}
	lock(t)
	e := cluster(t)

	must(t, 10*time.Minute, "docker", "build", "-t", image, repoRoot)
	must(t, 5*time.Minute, "kind", "load", "docker-image", image, "--name", clusterName)
	// A kept cluster may hold an earlier run's objects, so each run starts clean.
	e.mustKubectl("delete", "namespace", namespace, "--ignore-not-found", "--wait=true", "--timeout=3m")
	e.mustKubectl("create", "namespace", namespace)
	t.Cleanup(func() { _, _ = e.kubectl("delete", "namespace", namespace, "--wait=false") })

	type target struct{ Name, Variant, Instance string }
	e.apply("testdata/targets.yaml", map[string]any{"Image": image, "Targets": []target{
		{"baseline-a", "baseline", "a"}, {"baseline-b", "baseline", "b"}, {"candidate", "candidate", "c"},
	}})
	must(t, 6*time.Minute, "helm", "upgrade", "--install", release, repoRoot+"/deploy/helm/replaydiff",
		"--kubeconfig", e.kubeconfig, "--namespace", namespace, "--values", "testdata/values.yaml", "--wait", "--timeout", "5m")
	for _, name := range []string{"baseline-a", "baseline-b", "candidate"} {
		e.mustKubectl("rollout", "status", "deployment/"+name, "--timeout=3m")
	}

	service := release + "-replaydiff"
	url := e.portForward(service, 80)
	secret := newSentinel(t)
	auth := map[string]string{"Authorization": "Bearer " + secret}
	sent := 0
	send := func(path string) {
		if code, body := get(t, url+path+"?token="+secret, auth); code >= 500 && !strings.Contains(path, "missing") {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		sent++
	}
	for i := 1; i <= 5; i++ {
		send(fmt.Sprintf("/v1/orders/ord-%d", i))
		send(fmt.Sprintf("/v1/users/usr-%d", i))
		send(fmt.Sprintf("/v1/inventory/sku%d", i))
		send("/v1/catalog")
	}
	send("/v1/orders/ord-missing")
	for range 25 {
		send("/v1/reports/daily")
	}

	admin := e.portForward(service, 18209)
	persisted := fmt.Sprintf("replaydiff_capture_records_persisted_total %d\n", sent)
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, metrics := get(t, admin+"/metrics", nil)
		if strings.Contains(metrics, persisted) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics never showed %q:\n%s", strings.TrimSpace(persisted), metrics)
		}
		time.Sleep(time.Second)
	}

	// Stopping the pod seals its recording, which replay requires.
	pod := strings.TrimSpace(e.mustKubectl("get", "pods", "-l", "app.kubernetes.io/instance="+release, "-o", "jsonpath={.items[0].metadata.name}"))
	e.mustKubectl("scale", "deployment/"+service, "--replicas=0")
	e.mustKubectl("wait", "--for=delete", "pod/"+pod, "--timeout=2m")

	e.apply("testdata/replay-job.yaml", map[string]any{"Image": image, "Pod": pod, "Release": release})
	deadline = time.Now().Add(5 * time.Minute)
	for {
		status := e.mustKubectl("get", "job/replay", "-o", "jsonpath={.status.succeeded}/{.status.failed}")
		if status != "/" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the replay job didn't finish")
		}
		time.Sleep(2 * time.Second)
	}
	jobPod := strings.TrimSpace(e.mustKubectl("get", "pods", "-l", "job-name=replay", "-o", "jsonpath={.items[0].metadata.name}"))
	logs := map[string]string{}
	for _, c := range []string{"inspect", "run", "report"} {
		logs[c], _ = e.kubectl("logs", jobPod, "-c", c)
	}
	exit := func(field string) string {
		return e.mustKubectl("get", "pod", jobPod, "-o", "jsonpath={."+field+"[*].state.terminated.exitCode}")
	}
	if got := exit("status.initContainerStatuses"); got != "0 0" {
		t.Fatalf("inspect and run exits %q\ninspect:\n%s\nrun:\n%s", got, logs["inspect"], logs["run"])
	}
	if got := exit("status.containerStatuses"); got != "1" {
		t.Fatalf("report exit %q, want 1 for a regression:\n%s", got, logs["report"])
	}

	if !strings.Contains(logs["inspect"], fmt.Sprintf("%d record(s)", sent)) {
		t.Errorf("inspect didn't read %d records:\n%s", sent, tail(logs["inspect"]))
	}
	if !regexp.MustCompile(`findings: [1-9]\d* breaking`).MatchString(logs["run"]) {
		t.Errorf("run found nothing breaking:\n%s", logs["run"])
	}
	for _, want := range []string{"field_removed", "type_changed", "latency_regression"} {
		if !strings.Contains(logs["report"], want) {
			t.Errorf("report lacks %s:\n%s", want, logs["report"])
		}
	}
	for name, text := range logs {
		if strings.Contains(text, secret) {
			t.Errorf("the %s output holds the credential sent with the traffic", name)
		}
	}
}

func tail(s string) string {
	if len(s) > 2000 {
		return "..." + s[len(s)-2000:]
	}
	return s
}
