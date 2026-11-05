package telemetry

import (
	"encoding/json"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const dashboardPath = "../../deploy/grafana/replaydiff-capture.json"

type dashboard struct {
	Panels []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Datasource  struct {
			UID string `json:"uid"`
		} `json:"datasource"`
		Targets []struct {
			Expr string `json:"expr"`
		} `json:"targets"`
	} `json:"panels"`
}

var metricName = regexp.MustCompile(`\b(?:replaydiff|go|process)_[a-z_]+\b`)

// Dashboards drift from the code. Every metric the dashboard queries must exist, and
// every metric of capture's own must be on it.
func TestDashboardMatchesTheMetrics(t *testing.T) {
	data, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatal(err)
	}
	var d dashboard
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	metrics := testMetrics()
	metrics.ObserveExchange("http/1.1", 0)
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, family := range families {
		registered[family.GetName()] = true
	}

	used := map[string]bool{}
	for _, panel := range d.Panels {
		if panel.Title == "" || panel.Description == "" {
			t.Errorf("panel %q needs a title and a description", panel.Title)
		}
		if panel.Datasource.UID != "${datasource}" {
			t.Errorf("panel %q must use the datasource variable, not %q", panel.Title, panel.Datasource.UID)
		}
		for _, target := range panel.Targets {
			for _, name := range metricName.FindAllString(target.Expr, -1) {
				name = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_count"), "_sum")
				used[name] = true
				// Process metrics exist only where the platform provides them, Linux included.
				if strings.HasPrefix(name, "process_") && runtime.GOOS != "linux" {
					continue
				}
				if !registered[name] {
					t.Errorf("panel %q queries %s, which isn't registered", panel.Title, name)
				}
			}
		}
	}
	for name := range registered {
		if strings.HasPrefix(name, "replaydiff_") && !used[name] {
			t.Errorf("%s isn't on the dashboard", name)
		}
	}
}
