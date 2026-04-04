package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/workflow"
	yamlv3 "gopkg.in/yaml.v3"
)

type workflowAdapterSuite struct {
	Suite       string                   `yaml:"suite"`
	Version     int                      `yaml:"version"`
	Description string                   `yaml:"description"`
	Workflows   map[string]any           `yaml:"workflows"`
	Fixtures    []workflowAdapterFixture `yaml:"fixtures"`
}

type workflowAdapterFixture struct {
	ID           string                 `yaml:"id"`
	Workflow     string                 `yaml:"workflow"`
	Description  string                 `yaml:"description"`
	Lineage      workflowAdapterLineage `yaml:"lineage"`
	InitialState workflow.State         `yaml:"initial_state"`
	Steps        []workflowAdapterStep  `yaml:"steps"`
}

type workflowAdapterLineage struct {
	ParentSessionID string `yaml:"parent_session_id"`
}

type workflowAdapterStep struct {
	ID               string                `yaml:"id"`
	Call             workflowAdapterCall   `yaml:"call"`
	ApprovalOutcomes []string              `yaml:"approval_outcomes"`
	Execution        string                `yaml:"execution"`
	Expect           workflowAdapterExpect `yaml:"expect"`
}

type workflowAdapterCall struct {
	Tool string         `yaml:"tool"`
	Args map[string]any `yaml:"args"`
}

type workflowAdapterExpect struct {
	Decision        string                   `yaml:"decision"`
	ActiveStage     string                   `yaml:"active_stage"`
	CompletedStages []string                 `yaml:"completed_stages"`
	Approvals       map[string]string        `yaml:"approvals"`
	Evidence        workflow.Evidence        `yaml:"evidence"`
	BlockedReason   *string                  `yaml:"blocked_reason"`
	PendingApproval workflow.PendingApproval `yaml:"pending_approval"`
	AuditEvents     []map[string]any         `yaml:"audit_events"`
}

type loadedWorkflowAdapterSuite struct {
	path  string
	suite workflowAdapterSuite
}

func loadWorkflowAdapterSuites(t *testing.T) []loadedWorkflowAdapterSuite {
	t.Helper()

	dir, candidates, ok := resolveWorkflowAdapterFixturesDir()
	if !ok {
		if os.Getenv("EDICTUM_CONFORMANCE_REQUIRED") == "1" {
			t.Fatalf("EDICTUM_CONFORMANCE_REQUIRED=1 but workflow adapter fixtures not found in: %s", strings.Join(candidates, ", "))
		}
		t.Skipf("workflow adapter fixtures not found; tried: %s", strings.Join(candidates, ", "))
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.workflow-adapter.yaml"))
	if err != nil {
		t.Fatalf("Glob(%s): %v", dir, err)
	}
	if len(paths) == 0 {
		t.Fatalf("fixture directory %s contains no *.workflow-adapter.yaml files", dir)
	}

	suites := make([]loadedWorkflowAdapterSuite, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // Test-only fixture path under version control or explicit env var.
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", path, err)
		}
		var suite workflowAdapterSuite
		if err := yamlv3.Unmarshal(raw, &suite); err != nil {
			t.Fatalf("Unmarshal(%s): %v", path, err)
		}
		suites = append(suites, loadedWorkflowAdapterSuite{path: path, suite: suite})
	}
	return suites
}

func resolveWorkflowAdapterFixturesDir() (string, []string, bool) {
	candidates := []string{}
	if dir := os.Getenv("EDICTUM_WORKFLOW_ADAPTER_FIXTURES_DIR"); dir != "" {
		candidates = append(candidates, dir)
	}
	if dir := os.Getenv("EDICTUM_SCHEMAS_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "fixtures", "workflow-adapter-conformance"))
	}
	candidates = append(candidates,
		"fixtures/workflow-adapter-conformance",
		"../../edictum-schemas/fixtures/workflow-adapter-conformance",
	)

	for _, candidate := range candidates {
		//nolint:gosec // Test-only discovery from env vars plus fixed local fallbacks.
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, candidates, true
		}
	}
	return "", candidates, false
}
