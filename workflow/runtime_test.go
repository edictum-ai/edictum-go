package workflow

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func TestRuntime_ReadBeforeEditAndEvidenceAfterSuccess(t *testing.T) {
	rt := mustRuntime(t, `apiVersion: edictum/v1
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
	sess := newWorkflowSession(t, "wf-read-before-edit")
	ctx := context.Background()

	edit := makeCall(t, "Edit", map[string]any{"path": "src/app.ts"})
	decision, err := rt.Evaluate(ctx, sess, edit)
	if err != nil {
		t.Fatalf("Evaluate(edit): %v", err)
	}
	if decision.Action != ActionBlock || decision.Reason != "Read the workflow spec first" {
		t.Fatalf("unexpected edit decision: %+v", decision)
	}
	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State after blocked edit: %v", err)
	}
	if state.BlockedReason != "Read the workflow spec first" {
		t.Fatalf("BlockedReason = %q, want %q", state.BlockedReason, "Read the workflow spec first")
	}
	if state.PendingApproval.Required {
		t.Fatalf("PendingApproval.Required = true, want false")
	}
	if state.LastBlockedAction == nil {
		t.Fatal("expected LastBlockedAction to be recorded")
	}
	if state.LastBlockedAction.Tool != "Edit" {
		t.Fatalf("LastBlockedAction.Tool = %q, want %q", state.LastBlockedAction.Tool, "Edit")
	}
	if state.LastBlockedAction.Summary != "src/app.ts" {
		t.Fatalf("LastBlockedAction.Summary = %q, want %q", state.LastBlockedAction.Summary, "src/app.ts")
	}
	if state.LastBlockedAction.Message != "Read the workflow spec first" {
		t.Fatalf("LastBlockedAction.Message = %q, want %q", state.LastBlockedAction.Message, "Read the workflow spec first")
	}
	if state.LastBlockedAction.Timestamp == "" {
		t.Fatal("expected LastBlockedAction.Timestamp to be set")
	}

	read := makeCall(t, "Read", map[string]any{"path": "specs/008.md"})
	decision, err = rt.Evaluate(ctx, sess, read)
	if err != nil {
		t.Fatalf("Evaluate(read): %v", err)
	}
	if decision.Action != ActionAllow || decision.StageID != "read-context" {
		t.Fatalf("unexpected read decision: %+v", decision)
	}
	if _, err := rt.RecordResult(ctx, sess, decision.StageID, read); err != nil {
		t.Fatalf("RecordResult(read): %v", err)
	}

	state, err = rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if len(state.Evidence.Reads) != 1 || state.Evidence.Reads[0] != "specs/008.md" {
		t.Fatalf("unexpected reads: %+v", state.Evidence.Reads)
	}
	if state.BlockedReason != "" {
		t.Fatalf("BlockedReason after success = %q, want empty", state.BlockedReason)
	}
	if state.LastRecordedEvidence == nil {
		t.Fatal("expected LastRecordedEvidence after successful read")
	}
	if state.LastRecordedEvidence.Tool != "Read" {
		t.Fatalf("LastRecordedEvidence.Tool = %q, want %q", state.LastRecordedEvidence.Tool, "Read")
	}
	if state.LastRecordedEvidence.Summary != "specs/008.md" {
		t.Fatalf("LastRecordedEvidence.Summary = %q, want %q", state.LastRecordedEvidence.Summary, "specs/008.md")
	}
	if state.LastRecordedEvidence.Timestamp == "" {
		t.Fatal("expected LastRecordedEvidence.Timestamp to be set")
	}

	decision, err = rt.Evaluate(ctx, sess, edit)
	if err != nil {
		t.Fatalf("Evaluate(edit after read): %v", err)
	}
	if decision.Action != ActionAllow || decision.StageID != "implement" {
		t.Fatalf("unexpected edit decision after read: %+v", decision)
	}
}

func TestRuntime_ApprovalBoundaryAndReset(t *testing.T) {
	rt := mustRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: approval-process
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
	sess := newWorkflowSession(t, "wf-approval")
	ctx := context.Background()

	push := makeCall(t, "Bash", map[string]any{"command": "git push origin feature"})
	edit := makeCall(t, "Edit", map[string]any{"path": "src/app.ts"})
	decision, err := rt.Evaluate(ctx, sess, edit)
	if err != nil {
		t.Fatalf("Evaluate(edit before approval): %v", err)
	}
	if decision.Action != ActionAllow || decision.StageID != "implement" {
		t.Fatalf("unexpected edit decision: %+v", decision)
	}
	if _, err := rt.RecordResult(ctx, sess, decision.StageID, edit); err != nil {
		t.Fatalf("RecordResult(edit): %v", err)
	}
	decision, err = rt.Evaluate(ctx, sess, push)
	if err != nil {
		t.Fatalf("Evaluate(push before approval): %v", err)
	}
	if decision.Action != ActionPendingApproval || decision.StageID != "review" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State before approval: %v", err)
	}
	if state.BlockedReason != "Approval required before push" {
		t.Fatalf("BlockedReason = %q, want %q", state.BlockedReason, "Approval required before push")
	}
	if !state.PendingApproval.Required {
		t.Fatal("expected PendingApproval.Required to be true")
	}
	if state.PendingApproval.StageID != "review" {
		t.Fatalf("PendingApproval.StageID = %q, want %q", state.PendingApproval.StageID, "review")
	}
	if state.PendingApproval.Message != "Approval required before push" {
		t.Fatalf("PendingApproval.Message = %q, want %q", state.PendingApproval.Message, "Approval required before push")
	}
	if err := rt.RecordApproval(ctx, sess, "review"); err != nil {
		t.Fatalf("RecordApproval: %v", err)
	}
	decision, err = rt.Evaluate(ctx, sess, push)
	if err != nil {
		t.Fatalf("Evaluate(push after approval): %v", err)
	}
	if decision.Action != ActionAllow || decision.StageID != "push" {
		t.Fatalf("unexpected decision after approval: %+v", decision)
	}

	events, err := rt.Reset(ctx, sess, "implement")
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Reset events len = %d, want 1", len(events))
	}
	if got, _ := events[0]["action"].(string); got != "workflow_state_updated" {
		t.Fatalf("Reset action = %q, want %q", got, "workflow_state_updated")
	}
	workflowData, ok := events[0]["workflow"].(map[string]any)
	if !ok {
		t.Fatalf("Reset workflow payload type = %T, want map[string]any", events[0]["workflow"])
	}
	if workflowData["name"] != "approval-process" {
		t.Fatalf("Reset workflow name = %#v, want %q", workflowData["name"], "approval-process")
	}
	if workflowData["active_stage"] != "implement" {
		t.Fatalf("Reset active_stage = %#v, want %q", workflowData["active_stage"], "implement")
	}
	if pending, ok := workflowData["pending_approval"].(map[string]any); !ok {
		t.Fatalf("Reset pending_approval type = %T, want map[string]any", workflowData["pending_approval"])
	} else if pending["required"] != false {
		t.Fatalf("Reset pending_approval.required = %#v, want false", pending["required"])
	}
	completed, ok := workflowData["completed_stages"].([]any)
	if !ok {
		t.Fatalf("Reset completed_stages type = %T, want []any", workflowData["completed_stages"])
	}
	if len(completed) != 0 {
		t.Fatalf("Reset completed_stages = %#v, want empty", completed)
	}

	state, err = rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State after reset: %v", err)
	}
	if state.ActiveStage != "implement" || len(state.CompletedStages) != 0 {
		t.Fatalf("unexpected state after reset: %+v", state)
	}
	if len(state.Approvals) != 0 {
		t.Fatalf("expected approvals cleared, got %+v", state.Approvals)
	}
	if state.BlockedReason != "" {
		t.Fatalf("BlockedReason after reset = %q, want empty", state.BlockedReason)
	}
	if state.PendingApproval.Required {
		t.Fatal("expected reset to clear pending approval")
	}
}

func mustRuntime(t *testing.T, content string) *Runtime {
	t.Helper()
	return mustRuntimeWithOpts(t, content)
}

func mustRuntimeWithOpts(t *testing.T, content string, opts ...RuntimeOption) *Runtime {
	t.Helper()
	def, err := LoadString(content)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	rt, err := NewRuntime(def, opts...)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return rt
}

func newWorkflowSession(t *testing.T, id string) *session.Session {
	t.Helper()
	sess, err := session.New(id, session.NewMemoryBackend())
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	return sess
}

func makeCall(t *testing.T, tool string, args map[string]any) toolcall.ToolCall {
	t.Helper()
	call, err := toolcall.CreateToolCall(context.Background(), toolcall.CreateToolCallOptions{
		ToolName: tool,
		Args:     args,
	})
	if err != nil {
		t.Fatalf("CreateToolCall: %v", err)
	}
	return call
}
