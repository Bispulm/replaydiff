package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The Compose stack must parse, keep every published port on 127.0.0.1 within 18200 to
// 18209, and point at provisioning files that exist.
func TestComposeStackIsValid(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker isn't installed")
	}
	out, err := exec.CommandContext(t.Context(), "docker", "compose", "-f", "../../compose.yaml", "config", "--format", "yaml").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "is not a docker command") {
			t.Skip("docker compose isn't installed")
		}
		t.Fatalf("docker compose config: %v\n%s", err, out)
	}
	var config struct {
		Services map[string]struct {
			Ports []struct {
				HostIP    string `yaml:"host_ip"`
				Published string `yaml:"published"`
			} `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(out, &config); err != nil {
		t.Fatal(err)
	}
	published := 0
	for name, service := range config.Services {
		for _, port := range service.Ports {
			published++
			if port.HostIP != "127.0.0.1" || port.Published < "18200" || port.Published > "18209" || len(port.Published) != 5 {
				t.Errorf("%s publishes %s:%s, want 127.0.0.1 and a port from 18200 to 18209", name, port.HostIP, port.Published)
			}
		}
	}
	if published == 0 {
		t.Fatal("no published ports")
	}
	for _, path := range []string{
		"../../deploy/compose/prometheus.yml",
		"../../deploy/compose/grafana/datasources/prometheus.yaml",
		"../../deploy/compose/grafana/dashboards/replaydiff.yaml",
		"../../deploy/grafana/replaydiff-capture.json",
		"../../examples/redact.yaml",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Error(err)
		}
	}
}
