package e2e

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/Bispulm/replaydiff/internal/diff"
	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/report"
)

// Examples get copied, so they have to keep working as the rules change.
func TestExampleFilesAreValid(t *testing.T) {
	if _, err := redact.LoadPolicy("../../examples/redact.yaml"); err != nil {
		t.Errorf("redact.yaml: %v", err)
	}
	if _, err := report.LoadPolicy("../../examples/policy.yaml"); err != nil {
		t.Errorf("policy.yaml: %v", err)
	}
}

func TestDocumentedDiffConfigIsValid(t *testing.T) {
	doc, err := os.ReadFile("../../docs/diffing.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(doc), "```yaml\n")
	if !found {
		t.Fatal("no example in docs/diffing.md")
	}
	example, _, found := strings.Cut(rest, "```")
	if !found {
		t.Fatal("unterminated example")
	}
	if _, err := diff.ParseConfig([]byte(example)); err != nil {
		t.Fatalf("documented config is invalid: %v", err)
	}
}

type workflowStep struct {
	Name            string `yaml:"name"`
	If              string `yaml:"if"`
	Run             string `yaml:"run"`
	Uses            string `yaml:"uses"`
	ContinueOnError bool   `yaml:"continue-on-error"`
}

func loadSteps(t *testing.T, path, job string) []workflowStep {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	steps := workflow.Jobs[job].Steps
	if len(steps) == 0 {
		t.Fatalf("%s has no steps in job %s", path, job)
	}
	return steps
}

// The example's whole point is that its gate decides the job. Getting these details wrong
// would produce a workflow that looks right and never fails.
func TestExampleWorkflowLetsTheGateDecide(t *testing.T) {
	steps := loadSteps(t, "../../examples/github-actions/replay-gate.yml", "replay")
	find := func(name string) workflowStep {
		i := slices.IndexFunc(steps, func(s workflowStep) bool { return s.Name == name })
		if i < 0 {
			t.Fatalf("no step named %q", name)
		}
		return steps[i]
	}
	if !find("Replay").ContinueOnError {
		t.Error("a failed replay must still reach the gate")
	}
	gate := find("Gate")
	if gate.ContinueOnError {
		t.Error("the gate's exit code must decide the job")
	}
	if !strings.Contains(gate.Run, "replaydiff report") {
		t.Errorf("gate step = %q", gate.Run)
	}
	if strings.Contains(gate.Run, "|| true") {
		t.Error("the gate's exit code is being discarded")
	}
	if find("Publish the summary").If != "always()" {
		t.Error("the summary must be published when the gate fails")
	}
	if find("Keep the reports").If != "always()" {
		t.Error("the reports must be kept when the gate fails")
	}
}

func TestContinuousIntegrationProvesTheGate(t *testing.T) {
	steps := loadSteps(t, "../../.github/workflows/ci.yml", "gate")
	if !slices.ContainsFunc(steps, func(s workflowStep) bool {
		return strings.Contains(s.Run, "scripts/gate-demo.sh") && !s.ContinueOnError
	}) {
		t.Fatalf("steps = %+v", steps)
	}
}
