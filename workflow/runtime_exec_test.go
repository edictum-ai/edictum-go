package workflow

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/toolcall"
)

func TestRuntime_ExecAndCommandEvaluators(t *testing.T) {
	rt := mustRuntimeWithOpts(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: verify-process
stages:
  - id: local-verify
    tools: [Bash]
    checks:
      - command_matches: "^go version$"
        message: Only go version is allowed
    exit:
      - condition: exec("go version", exit_code=0)
        message: Go must be installed
  - id: commit-push
    entry:
      - condition: stage_complete("local-verify")
    tools: [Bash]
    checks:
      - command_not_matches: "^git push origin main$"
        message: Push to a branch, not main
    exit:
      - condition: command_not_matches("^git push origin main$")
        message: Push to a branch, not main
`, WithExecEvaluatorEnabled())
	sess := newWorkflowSession(t, "wf-evaluators")
	ctx := context.Background()

	verify := makeCall(t, "Bash", map[string]any{"command": "go version"})
	decision, err := rt.Evaluate(ctx, sess, verify)
	if err != nil {
		t.Fatalf("Evaluate(verify): %v", err)
	}
	if decision.Action != ActionAllow {
		t.Fatalf("unexpected verify decision: %+v", decision)
	}
	if _, err := rt.RecordResult(ctx, sess, decision.StageID, verify); err != nil {
		t.Fatalf("RecordResult(verify): %v", err)
	}

	mainPush := makeCall(t, "Bash", map[string]any{"command": "git push origin main"})
	decision, err = rt.Evaluate(ctx, sess, mainPush)
	if err != nil {
		t.Fatalf("Evaluate(main push): %v", err)
	}
	if decision.Action != ActionBlock || decision.Reason != "Push to a branch, not main" {
		t.Fatalf("unexpected main push decision: %+v", decision)
	}
}

func TestRuntime_ExecRequiresExplicitOptIn(t *testing.T) {
	def, err := LoadString(`apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-disabled
stages:
  - id: verify
    tools: [Bash]
    exit:
      - condition: exec("go version", exit_code=0)
        message: Go must be installed
`)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	_, err = NewRuntime(def)
	if err == nil {
		t.Fatal("expected exec opt-in error")
	}
}

func TestRuntime_EmptyToolsMeansAllToolsAllowed(t *testing.T) {
	rt := mustRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: unrestricted-stage
stages:
  - id: implement
`)
	sess := newWorkflowSession(t, "wf-empty-tools")
	decision, err := rt.Evaluate(context.Background(), sess, makeCall(t, "Edit", map[string]any{"path": "src/app.ts"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Fatalf("decision = %+v, want allow", decision)
	}
}

func TestRuntime_ToolsAllowlistIsAuthoritativeWhenPresent(t *testing.T) {
	rt := mustRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: listed-tools-only
stages:
  - id: inspect
    tools: [Read]
`)
	sess := newWorkflowSession(t, "wf-listed-tools-only")

	readDecision, err := rt.Evaluate(context.Background(), sess, makeCall(t, "Read", map[string]any{"path": "specs/008.md"}))
	if err != nil {
		t.Fatalf("Evaluate(Read): %v", err)
	}
	if readDecision.Action != ActionAllow {
		t.Fatalf("Read decision = %+v, want allow", readDecision)
	}

	editDecision, err := rt.Evaluate(context.Background(), sess, makeCall(t, "Edit", map[string]any{"path": "src/app.ts"}))
	if err != nil {
		t.Fatalf("Evaluate(Edit): %v", err)
	}
	if editDecision.Action != ActionBlock {
		t.Fatalf("Edit decision = %+v, want block", editDecision)
	}
}

func TestSecurityRuntime_StageToolsAllowlistBlocksReadAndGrep(t *testing.T) {
	rt := mustRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: inspection-tools
stages:
  - id: implement
    tools: [Edit]
`)
	sess := newWorkflowSession(t, "wf-inspection-tools")
	for _, call := range []toolcall.ToolCall{
		makeCall(t, "Read", map[string]any{"path": "specs/008.md"}),
		makeCall(t, "Grep", map[string]any{"path": "specs", "pattern": "workflow"}),
	} {
		decision, err := rt.Evaluate(context.Background(), sess, call)
		if err != nil {
			t.Fatalf("Evaluate(%s): %v", call.ToolName(), err)
		}
		if decision.Action != ActionBlock {
			t.Fatalf("%s decision = %+v, want block", call.ToolName(), decision)
		}
	}
}
