package guard

import (
	"context"
	"errors"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/workflow"
)

func TestRun_WorkflowEvidenceRecordedOnlyAfterSuccess(t *testing.T) {
	rt := mustWorkflowRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: core-dev-process
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("specs/008.md")
        message: Read the workflow spec first
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
`)
	g := New(WithWorkflowRuntime(rt))
	ctx := context.Background()

	_, err := g.Run(ctx, "Read", map[string]any{"path": "specs/008.md"}, failCallable)
	if err == nil {
		t.Fatal("expected tool failure")
	}

	state, err := workflowState(ctx, rt, g.sessionID, g)
	if err != nil {
		t.Fatalf("workflowState after failed read: %v", err)
	}
	if len(state.Evidence.Reads) != 0 {
		t.Fatalf("expected no read evidence after failed read, got %+v", state.Evidence.Reads)
	}

	_, err = g.Run(ctx, "Edit", map[string]any{"path": "src/app.ts"}, nopCallable)
	if err == nil {
		t.Fatal("expected workflow block")
	}
	var blocked *edictum.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected BlockedError, got %T", err)
	}

	events := g.LocalSink().Events()
	foundWorkflowBlock := false
	for _, event := range events {
		if event.Action == audit.ActionCallBlocked && event.Workflow != nil {
			if event.Workflow["workflow_name"] == "core-dev-process" {
				foundWorkflowBlock = true
			}
		}
	}
	if !foundWorkflowBlock {
		t.Fatal("expected blocked audit event with workflow metadata")
	}
}

func TestRun_WorkflowApprovalBoundaryReevaluatesSameCall(t *testing.T) {
	rt := mustWorkflowRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: push-process
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Approval required before push
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
    checks:
      - command_not_matches: "^git push origin main$"
        message: Push to a branch, not main
`)
	g := New(
		WithWorkflowRuntime(rt),
		WithApprovalBackend(&autoApproveBackend{}),
	)
	ctx := context.Background()

	if _, err := g.Run(ctx, "Edit", map[string]any{"path": "src/app.ts"}, nopCallable); err != nil {
		t.Fatalf("Run(Edit): %v", err)
	}
	result, err := g.Run(ctx, "Bash", map[string]any{"command": "git push origin feature-branch"}, nopCallable)
	if err != nil {
		t.Fatalf("Run(Bash push): %v", err)
	}
	if result != "ok" {
		t.Fatalf("result = %v, want ok", result)
	}

	state, err := workflowState(ctx, rt, g.sessionID, g)
	if err != nil {
		t.Fatalf("workflowState: %v", err)
	}
	if state.Approvals["review"] != "approved" {
		t.Fatalf("expected review approval to persist, got %+v", state.Approvals)
	}
	if got := state.Evidence.StageCalls["push"]; len(got) != 1 || got[0] != "git push origin feature-branch" {
		t.Fatalf("unexpected push evidence: %+v", got)
	}

	events := g.LocalSink().Events()
	sawApprovalRequested := false
	sawAllowedWithWorkflow := false
	sawStageAdvanced := false
	for _, event := range events {
		if event.Action == audit.ActionCallApprovalRequested && event.Workflow != nil {
			sawApprovalRequested = true
		}
		if event.Action == audit.ActionCallAllowed && event.Workflow != nil {
			if event.Workflow["stage_id"] == "push" {
				sawAllowedWithWorkflow = true
			}
		}
		if event.Action == audit.ActionWorkflowStageAdvanced && event.Workflow != nil {
			sawStageAdvanced = true
		}
	}
	if !sawApprovalRequested {
		t.Fatal("expected workflow approval request audit event")
	}
	if !sawAllowedWithWorkflow {
		t.Fatal("expected allowed audit event with workflow stage metadata")
	}
	if !sawStageAdvanced {
		t.Fatal("expected workflow stage advanced audit event")
	}
}

func TestRun_WorkflowCompletionEmitsAuditEvent(t *testing.T) {
	rt := mustWorkflowRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: completion-process
stages:
  - id: verify
    tools: [Bash]
    exit:
      - condition: command_matches("^npm test$")
        message: Run npm test
`)
	g := New(WithWorkflowRuntime(rt))

	if _, err := g.Run(context.Background(), "Bash", map[string]any{"command": "npm test"}, nopCallable); err != nil {
		t.Fatalf("Run(Bash): %v", err)
	}

	events := g.LocalSink().Events()
	for _, event := range events {
		if event.Action == audit.ActionWorkflowCompleted && event.Workflow != nil {
			if event.Workflow["workflow_name"] == "completion-process" {
				return
			}
		}
	}
	t.Fatal("expected workflow completed audit event")
}

func mustWorkflowRuntime(t *testing.T, content string) *workflow.Runtime {
	t.Helper()
	def, err := workflow.LoadString(content)
	if err != nil {
		t.Fatalf("workflow.LoadString: %v", err)
	}
	rt, err := workflow.NewRuntime(def)
	if err != nil {
		t.Fatalf("workflow.NewRuntime: %v", err)
	}
	return rt
}

func workflowState(ctx context.Context, rt *workflow.Runtime, sessionID string, g *Guard) (workflow.State, error) {
	sess, err := session.New(sessionID, g.backend)
	if err != nil {
		return workflow.State{}, err
	}
	return rt.State(ctx, sess)
}
