package workflow

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/session"
	yamlv3 "gopkg.in/yaml.v3"
)

type fixtureSuite struct {
	Workflows map[string]any        `yaml:"workflows"`
	Fixtures  []workflowFixtureCase `yaml:"fixtures"`
}

type workflowFixtureCase struct {
	ID           string         `yaml:"id"`
	Workflow     string         `yaml:"workflow"`
	InitialState State          `yaml:"initial_state"`
	Steps        []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	ID        string         `yaml:"id"`
	Call      workflowCall   `yaml:"call"`
	Execution string         `yaml:"execution"`
	Expect    workflowExpect `yaml:"expect"`
}

type workflowCall struct {
	Tool string         `yaml:"tool"`
	Args map[string]any `yaml:"args"`
}

type workflowExpect struct {
	Decision             string            `yaml:"decision"`
	ActiveStage          string            `yaml:"active_stage"`
	CompletedStages      []string          `yaml:"completed_stages"`
	Approvals            map[string]string `yaml:"approvals"`
	Evidence             Evidence          `yaml:"evidence"`
	MessageContains      string            `yaml:"message_contains"`
	ApprovalRequestedFor string            `yaml:"approval_requested_for"`
}

func TestSharedWorkflowFixtures(t *testing.T) {
	path, ok := resolveWorkflowFixturesPath()
	if !ok {
		t.Skip("shared workflow fixtures not found")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // Test-only fixture path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var suite fixtureSuite
	if err := yamlv3.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	runtimes := map[string]*Runtime{}
	for name, doc := range suite.Workflows {
		docBytes, err := yamlv3.Marshal(doc)
		if err != nil {
			t.Fatalf("Marshal workflow %s: %v", name, err)
		}
		runtimes[name] = mustRuntime(t, string(docBytes))
	}

	for _, fixture := range suite.Fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			rt := runtimes[fixture.Workflow]
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
					t.Fatalf("Evaluate(%s): %v", step.ID, err)
				}
				if normalizeDecision(decision.Action) != step.Expect.Decision {
					t.Fatalf("%s decision = %q, want %q", step.ID, normalizeDecision(decision.Action), step.Expect.Decision)
				}
				if step.Expect.MessageContains != "" && !strings.Contains(decision.Reason, step.Expect.MessageContains) {
					t.Fatalf("%s reason = %q, want substring %q", step.ID, decision.Reason, step.Expect.MessageContains)
				}
				if step.Expect.ApprovalRequestedFor != "" {
					if got, _ := decision.Audit["approval_requested_for"].(string); got != step.Expect.ApprovalRequestedFor {
						t.Fatalf("%s approval_requested_for = %q, want %q", step.ID, got, step.Expect.ApprovalRequestedFor)
					}
				}
				if decision.Action == ActionAllow && step.Execution == "success" {
					if _, err := rt.RecordResult(context.Background(), sess, decision.StageID, call); err != nil {
						t.Fatalf("RecordResult(%s): %v", step.ID, err)
					}
				}
				state, err := rt.State(context.Background(), sess)
				if err != nil {
					t.Fatalf("State(%s): %v", step.ID, err)
				}
				assertState(t, step.ID, state, step.Expect)
			}
		})
	}
}

func resolveWorkflowFixturesPath() (string, bool) {
	candidates := []string{}
	if dir := os.Getenv("EDICTUM_SCHEMAS_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "fixtures", "workflow", "core.workflow.yaml"))
	}
	candidates = append(candidates,
		"fixtures/workflow/core.workflow.yaml",
		"../../edictum-schemas/fixtures/workflow/core.workflow.yaml",
	)
	for _, candidate := range candidates {
		//nolint:gosec // Test-only fixture discovery from env vars plus fixed local fallbacks.
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

func seedState(ctx context.Context, rt *Runtime, sess *session.Session, state State) error {
	state.ensureMaps()
	return saveState(ctx, sess, rt.Definition(), state)
}

func normalizeDecision(action string) string {
	if action == ActionPendingApproval {
		return "pause"
	}
	if action == ActionBlock {
		return "deny"
	}
	return action
}

func assertState(t *testing.T, stepID string, got State, expect workflowExpect) {
	t.Helper()
	if got.ActiveStage != expect.ActiveStage {
		t.Fatalf("%s active_stage = %q, want %q", stepID, got.ActiveStage, expect.ActiveStage)
	}
	if strings.Join(got.CompletedStages, ",") != strings.Join(expect.CompletedStages, ",") {
		t.Fatalf("%s completed_stages = %+v, want %+v", stepID, got.CompletedStages, expect.CompletedStages)
	}
	if strings.Join(got.Evidence.Reads, ",") != strings.Join(expect.Evidence.Reads, ",") {
		t.Fatalf("%s reads = %+v, want %+v", stepID, got.Evidence.Reads, expect.Evidence.Reads)
	}
	for stageID, expectCalls := range expect.Evidence.StageCalls {
		gotCalls := got.Evidence.StageCalls[stageID]
		if strings.Join(gotCalls, ",") != strings.Join(expectCalls, ",") {
			t.Fatalf("%s stage_calls[%s] = %+v, want %+v", stepID, stageID, gotCalls, expectCalls)
		}
	}
	if len(got.Approvals) != len(expect.Approvals) {
		t.Fatalf("%s approvals = %+v, want %+v", stepID, got.Approvals, expect.Approvals)
	}
	for stageID, status := range expect.Approvals {
		if got.Approvals[stageID] != status {
			t.Fatalf("%s approval[%s] = %q, want %q", stepID, stageID, got.Approvals[stageID], status)
		}
	}
}
