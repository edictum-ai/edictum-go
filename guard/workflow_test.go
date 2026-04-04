package guard

import (
	"context"
	"errors"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/pipeline"
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
			if event.Workflow["name"] == "core-dev-process" && event.Workflow["blocked_reason"] == "Read the workflow spec first" {
				if event.SessionID != g.sessionID {
					t.Fatalf("blocked event SessionID = %q, want %q", event.SessionID, g.sessionID)
				}
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
		if event.Action == audit.ActionCallAsked && event.Workflow != nil {
			if event.Workflow["name"] == "push-process" {
				if pending, ok := event.Workflow["pending_approval"].(map[string]any); ok && pending["required"] == true {
					sawApprovalRequested = true
				}
			}
		}
		if event.Action == audit.ActionCallAllowed && event.Workflow != nil {
			if event.Workflow["active_stage"] == "push" {
				if event.SessionID != g.sessionID {
					t.Fatalf("allowed event SessionID = %q, want %q", event.SessionID, g.sessionID)
				}
				sawAllowedWithWorkflow = true
			}
		}
		if event.Action == audit.ActionWorkflowStageAdvanced && event.Workflow != nil {
			if event.Workflow["name"] == "push-process" {
				sawStageAdvanced = true
			}
		}
	}
	if !sawApprovalRequested {
		t.Fatal("expected workflow call_asked audit event")
	}
	if !sawAllowedWithWorkflow {
		t.Fatal("expected allowed audit event with workflow stage metadata")
	}
	if !sawStageAdvanced {
		t.Fatal("expected workflow stage advanced audit event")
	}
}

func TestRun_WorkflowStageAdvanceEmittedWhenApprovalPauses(t *testing.T) {
	rt := mustWorkflowRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: approval-pause-process
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
`)
	g := New(
		WithWorkflowRuntime(rt),
		WithApprovalBackend(&autoDenyBackend{}),
	)

	if _, err := g.Run(context.Background(), "Edit", map[string]any{"path": "src/app.ts"}, nopCallable); err != nil {
		t.Fatalf("Run(Edit): %v", err)
	}
	_, err := g.Run(context.Background(), "Bash", map[string]any{"command": "git push origin feature-branch"}, nopCallable)
	if err == nil {
		t.Fatal("expected approval block")
	}

	events := g.LocalSink().Events()
	stageAdvancedIdx := -1
	approvalRequestedIdx := -1
	for idx, event := range events {
		if event.Action == audit.ActionWorkflowStageAdvanced && event.Workflow != nil {
			if event.Workflow["name"] == "approval-pause-process" && event.Workflow["active_stage"] == "review" {
				stageAdvancedIdx = idx
			}
		}
		if event.Action == audit.ActionCallAsked && event.Workflow != nil {
			if event.Workflow["name"] == "approval-pause-process" {
				if pending, ok := event.Workflow["pending_approval"].(map[string]any); ok && pending["required"] == true {
					approvalRequestedIdx = idx
				}
			}
		}
	}
	if stageAdvancedIdx == -1 {
		t.Fatal("expected workflow stage advanced event before approval resolution")
	}
	if approvalRequestedIdx == -1 {
		t.Fatal("expected call_asked audit event")
	}
	if stageAdvancedIdx >= approvalRequestedIdx {
		t.Fatalf("expected stage advance before approval request, got stage idx=%d approval idx=%d", stageAdvancedIdx, approvalRequestedIdx)
	}
}

func TestRun_WorkflowStageAdvanceEmittedWhenLaterLimitBlocks(t *testing.T) {
	rt := mustWorkflowRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: limit-block-process
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
	limits := pipeline.DefaultLimits()
	limits.MaxToolCalls = 1
	g := New(
		WithWorkflowRuntime(rt),
		WithLimits(limits),
	)

	if _, err := g.Run(context.Background(), "Read", map[string]any{"path": "specs/008.md"}, nopCallable); err != nil {
		t.Fatalf("Run(Read): %v", err)
	}
	_, err := g.Run(context.Background(), "Edit", map[string]any{"path": "src/app.ts"}, nopCallable)
	if err == nil {
		t.Fatal("expected execution limit block")
	}
	var blocked *edictum.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected BlockedError, got %T", err)
	}
	if blocked.DecisionSource != "operation_limit" {
		t.Fatalf("DecisionSource = %q, want operation_limit", blocked.DecisionSource)
	}

	events := g.LocalSink().Events()
	stageAdvancedIdx := -1
	limitBlockIdx := -1
	for idx, event := range events {
		if event.Action == audit.ActionWorkflowStageAdvanced && event.Workflow != nil {
			if event.Workflow["name"] == "limit-block-process" && event.Workflow["active_stage"] == "implement" {
				stageAdvancedIdx = idx
			}
		}
		if event.Action == audit.ActionCallBlocked && event.DecisionSource == "operation_limit" {
			limitBlockIdx = idx
		}
	}
	if stageAdvancedIdx == -1 {
		t.Fatal("expected workflow stage advanced event before later pre-execute block")
	}
	if limitBlockIdx == -1 {
		t.Fatal("expected later operation limit block audit event")
	}
	if stageAdvancedIdx >= limitBlockIdx {
		t.Fatalf("expected stage advance before block, got stage idx=%d block idx=%d", stageAdvancedIdx, limitBlockIdx)
	}
}

func TestRun_WorkflowStageAdvanceEmittedAcrossChainedApprovalRounds(t *testing.T) {
	rt := mustWorkflowRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: chained-approval-process
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Approval required before verify
  - id: verify
    entry:
      - condition: stage_complete("review")
    approval:
      message: Approval required before push
  - id: push
    entry:
      - condition: stage_complete("verify")
    tools: [Bash]
`)
	g := New(
		WithWorkflowRuntime(rt),
		WithApprovalBackend(&autoApproveBackend{}),
	)

	if _, err := g.Run(context.Background(), "Edit", map[string]any{"path": "src/app.ts"}, nopCallable); err != nil {
		t.Fatalf("Run(Edit): %v", err)
	}
	if _, err := g.Run(context.Background(), "Bash", map[string]any{"command": "git push origin feature-branch"}, nopCallable); err != nil {
		t.Fatalf("Run(Bash): %v", err)
	}

	events := g.LocalSink().Events()
	reviewAdvanceIdx := -1
	verifyAdvanceIdx := -1
	for idx, event := range events {
		if event.Action != audit.ActionWorkflowStageAdvanced || event.Workflow == nil {
			continue
		}
		if event.Workflow["name"] != "chained-approval-process" {
			continue
		}
		completed := workflowCompletedStages(event.Workflow)
		if event.Workflow["active_stage"] == "review" && len(completed) == 1 && completed[0] == "implement" {
			reviewAdvanceIdx = idx
		}
		if event.Workflow["active_stage"] == "verify" && len(completed) == 2 && completed[0] == "implement" && completed[1] == "review" {
			verifyAdvanceIdx = idx
		}
	}
	if reviewAdvanceIdx == -1 {
		t.Fatal("expected implement -> review stage advance event")
	}
	if verifyAdvanceIdx == -1 {
		t.Fatal("expected review -> verify stage advance event across chained approvals")
	}
	if reviewAdvanceIdx >= verifyAdvanceIdx {
		t.Fatalf("expected implement->review before review->verify, got %d >= %d", reviewAdvanceIdx, verifyAdvanceIdx)
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
			if event.Workflow["name"] == "completion-process" {
				return
			}
		}
	}
	t.Fatal("expected workflow completed audit event")
}

func workflowCompletedStages(workflow map[string]any) []string {
	raw, _ := workflow["completed_stages"].([]any)
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if stageID, ok := item.(string); ok {
			result = append(result, stageID)
		}
	}
	return result
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
