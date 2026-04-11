package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/session"
	yamlv3 "gopkg.in/yaml.v3"
)

// v018FixtureSuite is the top-level structure of a workflow-v0.18 fixture file.
type v018FixtureSuite struct {
	Suite     string            `yaml:"suite"`
	Workflows map[string]any    `yaml:"workflows"`
	Fixtures  []v018FixtureCase `yaml:"fixtures"`
}

type v018FixtureCase struct {
	ID           string     `yaml:"id"`
	Workflow     string     `yaml:"workflow"`
	Description  string     `yaml:"description"`
	InitialState State      `yaml:"initial_state"`
	Steps        []v018Step `yaml:"steps"`
}

type v018Step struct {
	ID        string         `yaml:"id"`
	Call      workflowCall   `yaml:"call"`
	MCPResult map[string]any `yaml:"mcp_result,omitempty"`
	Execution string         `yaml:"execution"`
	Expect    v018Expect     `yaml:"expect"`
}

type v018Expect struct {
	Decision        string            `yaml:"decision"`
	ActiveStage     string            `yaml:"active_stage"`
	CompletedStages []string          `yaml:"completed_stages"`
	Approvals       map[string]string `yaml:"approvals"`
	Evidence        Evidence          `yaml:"evidence"`
	MessageContains string            `yaml:"message_contains"`
}

func TestV018WorkflowFixtures(t *testing.T) {
	dir, ok := resolveV018FixturesDir()
	if !ok {
		t.Skip("workflow-v0.18 fixtures not found; place edictum-schemas as sibling or set EDICTUM_SCHEMAS_DIR")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".workflow-v0.18.yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path) //nolint:gosec // Test-only fixture discovery.
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}

		var suite v018FixtureSuite
		if err := yamlv3.Unmarshal(raw, &suite); err != nil {
			t.Fatalf("Unmarshal(%s): %v", name, err)
		}

		// Skip non-workflow fixture files (e.g. extends-inheritance uses rulesets:).
		if len(suite.Workflows) == 0 {
			continue
		}

		runtimes := map[string]*Runtime{}
		for wfName, doc := range suite.Workflows {
			docBytes, err := yamlv3.Marshal(doc)
			if err != nil {
				t.Fatalf("Marshal workflow %s: %v", wfName, err)
			}
			runtimes[wfName] = mustRuntime(t, string(docBytes))
		}

		for _, fixture := range suite.Fixtures {
			t.Run(fixture.ID, func(t *testing.T) {
				rt := runtimes[fixture.Workflow]
				if rt == nil {
					t.Fatalf("no runtime for workflow %q", fixture.Workflow)
				}

				sess, err := session.New(fixture.InitialState.SessionID, session.NewMemoryBackend())
				if err != nil {
					t.Fatalf("session.New: %v", err)
				}
				if err := seedState(context.Background(), rt, sess, fixture.InitialState); err != nil {
					t.Fatalf("seedState: %v", err)
				}

				for _, step := range fixture.Steps {
					call := makeCall(t, step.Call.Tool, step.Call.Args)
					decision, err := rt.Evaluate(context.Background(), sess, call)
					if err != nil {
						t.Fatalf("[%s] Evaluate: %v", step.ID, err)
					}

					gotDecision := normalizeDecision(decision.Action)
					if gotDecision != step.Expect.Decision {
						t.Fatalf("[%s] decision = %q, want %q", step.ID, gotDecision, step.Expect.Decision)
					}
					if step.Expect.MessageContains != "" && !strings.Contains(decision.Reason, step.Expect.MessageContains) {
						t.Fatalf("[%s] reason = %q, want substring %q", step.ID, decision.Reason, step.Expect.MessageContains)
					}

					if decision.Action == ActionAllow && step.Execution == "success" {
						args := []map[string]any{}
						if step.MCPResult != nil {
							args = append(args, step.MCPResult)
						}
						if _, err := rt.RecordResult(context.Background(), sess, decision.StageID, call, args...); err != nil {
							t.Fatalf("[%s] RecordResult: %v", step.ID, err)
						}
					}

					state, err := rt.State(context.Background(), sess)
					if err != nil {
						t.Fatalf("[%s] State: %v", step.ID, err)
					}
					assertV018State(t, step.ID, state, step.Expect)
				}
			})
		}
	}
}

func resolveV018FixturesDir() (string, bool) {
	candidates := []string{}
	if dir := os.Getenv("EDICTUM_SCHEMAS_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "fixtures", "workflow-v0.18"))
	}
	candidates = append(candidates,
		"../../edictum-schemas/fixtures/workflow-v0.18",
	)
	for _, c := range candidates {
		//nolint:gosec // Test-only fixture discovery from known env vars + fixed paths.
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c, true
		}
	}
	return "", false
}

func assertV018State(t *testing.T, stepID string, got State, expect v018Expect) {
	t.Helper()
	if got.ActiveStage != expect.ActiveStage {
		t.Fatalf("[%s] active_stage = %q, want %q", stepID, got.ActiveStage, expect.ActiveStage)
	}
	if strings.Join(got.CompletedStages, ",") != strings.Join(expect.CompletedStages, ",") {
		t.Fatalf("[%s] completed_stages = %v, want %v", stepID, got.CompletedStages, expect.CompletedStages)
	}
	if strings.Join(got.Evidence.Reads, ",") != strings.Join(expect.Evidence.Reads, ",") {
		t.Fatalf("[%s] reads = %v, want %v", stepID, got.Evidence.Reads, expect.Evidence.Reads)
	}
	for stageID, expectCalls := range expect.Evidence.StageCalls {
		gotCalls := got.Evidence.StageCalls[stageID]
		if strings.Join(gotCalls, ",") != strings.Join(expectCalls, ",") {
			t.Fatalf("[%s] stage_calls[%s] = %v, want %v", stepID, stageID, gotCalls, expectCalls)
		}
	}
	if len(got.Approvals) != len(expect.Approvals) {
		t.Fatalf("[%s] approvals = %v, want %v", stepID, got.Approvals, expect.Approvals)
	}
	for stageID, status := range expect.Approvals {
		if got.Approvals[stageID] != status {
			t.Fatalf("[%s] approval[%s] = %q, want %q", stepID, stageID, got.Approvals[stageID], status)
		}
	}

	// Assert MCP result evidence.
	for toolName, expectResults := range expect.Evidence.MCPResults {
		gotResults := got.Evidence.MCPResults[toolName]
		if len(gotResults) != len(expectResults) {
			t.Fatalf("[%s] mcp_results[%s] len = %d, want %d", stepID, toolName, len(gotResults), len(expectResults))
		}
		for i, expectResult := range expectResults {
			gotResult := gotResults[i]
			if err := compareMCPResult(gotResult, expectResult); err != nil {
				t.Fatalf("[%s] mcp_results[%s][%d]: %v", stepID, toolName, i, err)
			}
		}
	}
	// Verify no unexpected MCP results were recorded.
	for toolName := range got.Evidence.MCPResults {
		if len(got.Evidence.MCPResults[toolName]) > 0 {
			if _, expected := expect.Evidence.MCPResults[toolName]; !expected {
				if expectMCPResultsEmpty(expect.Evidence.MCPResults) {
					t.Fatalf("[%s] unexpected mcp_results for tool %q", stepID, toolName)
				}
			}
		}
	}
}

func expectMCPResultsEmpty(m map[string][]map[string]any) bool {
	for _, v := range m {
		if len(v) > 0 {
			return false
		}
	}
	return true
}

// compareMCPResult checks that gotResult contains all keys from expectResult
// with matching values, using JSON-round-trip for type normalization.
func compareMCPResult(got, expect map[string]any) error {
	// Normalize via JSON to handle type differences between YAML unmarshal paths.
	gotJSON, err := json.Marshal(got)
	if err != nil {
		return fmt.Errorf("marshal got: %w", err)
	}
	expectJSON, err := json.Marshal(expect)
	if err != nil {
		return fmt.Errorf("marshal expect: %w", err)
	}

	var gotNorm, expectNorm map[string]any
	if err := json.Unmarshal(gotJSON, &gotNorm); err != nil {
		return fmt.Errorf("unmarshal got: %w", err)
	}
	if err := json.Unmarshal(expectJSON, &expectNorm); err != nil {
		return fmt.Errorf("unmarshal expect: %w", err)
	}

	for k, ev := range expectNorm {
		gv, ok := gotNorm[k]
		if !ok {
			return fmt.Errorf("missing key %q", k)
		}
		if fmt.Sprintf("%v", gv) != fmt.Sprintf("%v", ev) {
			return fmt.Errorf("key %q: got %v, want %v", k, gv, ev)
		}
	}
	return nil
}
