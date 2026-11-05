package e2e

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const chart = "../../deploy/helm/replaydiff"

func helm(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm isn't installed")
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(t.Context(), "helm", args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// render returns the chart's manifests by kind.
func render(t *testing.T, set ...string) map[string]map[string]any {
	t.Helper()
	args := []string{"template", "orders", chart, "--set", "app.image.repository=example/orders"}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	out, err := helm(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	docs := map[string]map[string]any{}
	decoder := yaml.NewDecoder(strings.NewReader(out))
	for {
		var doc map[string]any
		if err := decoder.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if doc != nil {
			docs[doc["kind"].(string)] = doc
		}
	}
	return docs
}

// dig follows keys and list indexes through decoded YAML.
func dig(v any, path ...any) any {
	for _, p := range path {
		switch key := p.(type) {
		case string:
			m, _ := v.(map[string]any)
			v = m[key]
		case int:
			l, _ := v.([]any)
			if key >= len(l) {
				return nil
			}
			v = l[key]
		}
	}
	return v
}

func container(t *testing.T, docs map[string]map[string]any, name string) map[string]any {
	t.Helper()
	containers, _ := dig(docs["Deployment"], "spec", "template", "spec", "containers").([]any)
	for _, c := range containers {
		if c.(map[string]any)["name"] == name {
			return c.(map[string]any)
		}
	}
	t.Fatalf("no %s container", name)
	return nil
}

func args(c map[string]any) []string {
	var out []string
	for _, a := range c["args"].([]any) {
		out = append(out, a.(string))
	}
	return out
}

func TestChartPassesLintAndRequiresTheServiceImage(t *testing.T) {
	if out, err := helm(t, "lint", chart, "--strict", "--set", "app.image.repository=example/orders"); err != nil {
		t.Fatalf("lint: %v\n%s", err, out)
	}
	if out, err := helm(t, "lint", chart, "--strict"); err == nil || !strings.Contains(out, "repository") {
		t.Fatalf("lint without the service's image must fail: %s", out)
	}
}

// The Service sends traffic to capture, which forwards to the service on localhost, and
// probes and scrapes use the admin port.
func TestChartPutsCaptureInFrontOfTheService(t *testing.T) {
	docs := render(t)
	capture := container(t, docs, "capture")
	got := args(capture)
	for _, want := range []string{"capture", "--listen=0.0.0.0:18200", "--admin-listen=0.0.0.0:18209", "--upstream=http://127.0.0.1:8080",
		"--out=/var/lib/replaydiff/$(POD_NAME)", "--redact=/etc/replaydiff/redact.yaml"} {
		if !slices.Contains(got, want) {
			t.Errorf("capture args lack %q: %v", want, got)
		}
	}
	if dig(docs["Service"], "spec", "ports", 0, "targetPort") != "capture" {
		t.Errorf("service ports = %v", dig(docs["Service"], "spec", "ports"))
	}
	if dig(capture, "readinessProbe", "httpGet", "path") != "/readyz" || dig(capture, "livenessProbe", "httpGet", "path") != "/livez" {
		t.Errorf("probes: %v, %v", capture["readinessProbe"], capture["livenessProbe"])
	}
	if !strings.Contains(dig(docs["ConfigMap"], "data", "redact.yaml").(string), "query_params: [token]") {
		t.Errorf("policy = %v", dig(docs["ConfigMap"], "data"))
	}
	for _, name := range []string{"app", "capture"} {
		c := container(t, docs, name)
		if dig(c, "securityContext", "readOnlyRootFilesystem") != true || dig(c, "securityContext", "allowPrivilegeEscalation") != false {
			t.Errorf("%s security context = %v", name, c["securityContext"])
		}
		if dig(c, "lifecycle", "preStop", "sleep", "seconds") != 5 {
			t.Errorf("%s has no preStop pause", name)
		}
	}
	if dig(docs["Deployment"], "spec", "template", "spec", "securityContext", "runAsNonRoot") != true {
		t.Error("the pod must run as non-root")
	}
	if dig(docs["Deployment"], "spec", "template", "spec", "volumes", 1, "emptyDir", "sizeLimit") != "2Gi" {
		t.Errorf("volumes = %v", dig(docs["Deployment"], "spec", "template", "spec", "volumes"))
	}
	if _, ok := docs["PersistentVolumeClaim"]; ok {
		t.Error("no claim unless asked for")
	}
}

func TestChartOptions(t *testing.T) {
	docs := render(t, "storage.persistentVolumeClaim.enabled=true", "capture.descriptorSet.configMap=orders-descriptors",
		"capture.sessionSecret.secretName=sessions", "capture.otlpEndpoint=http://collector:4318", "capture.h2c=true", "capture.upstreamH2C=true")
	if dig(docs["PersistentVolumeClaim"], "spec", "resources", "requests", "storage") != "1Gi" {
		t.Errorf("claim = %v", docs["PersistentVolumeClaim"])
	}
	capture := container(t, docs, "capture")
	got := args(capture)
	for _, want := range []string{"--descriptor-set=/etc/replaydiff/descriptors/descriptors.binpb", "--session-secret-env=REPLAYDIFF_SESSION_SECRET", "--h2c", "--upstream-h2c"} {
		if !slices.Contains(got, want) {
			t.Errorf("capture args lack %q: %v", want, got)
		}
	}
	env := map[string]any{}
	for _, e := range capture["env"].([]any) {
		env[e.(map[string]any)["name"].(string)] = e
	}
	if dig(env["REPLAYDIFF_SESSION_SECRET"], "valueFrom", "secretKeyRef", "name") != "sessions" || dig(env["OTEL_EXPORTER_OTLP_ENDPOINT"], "value") != "http://collector:4318" {
		t.Errorf("env = %v", capture["env"])
	}
	if dig(docs["Service"], "spec", "ports", 0, "appProtocol") != "kubernetes.io/h2c" {
		t.Errorf("service ports = %v", dig(docs["Service"], "spec", "ports"))
	}
}

func TestChartRefusesClashingPorts(t *testing.T) {
	if out, err := helm(t, "template", "orders", chart, "--set", "app.image.repository=example/orders", "--set", "app.port=18200"); err == nil || !strings.Contains(out, "must all differ") {
		t.Fatalf("a port clash must fail: %s", out)
	}
}
