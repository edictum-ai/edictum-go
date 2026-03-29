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

	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if len(state.Evidence.Reads) != 1 || state.Evidence.Reads[0] != "specs/008.md" {
		t.Fatalf("unexpected reads: %+v", state.Evidence.Reads)
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
	decision, err := rt.Evaluate(ctx, sess, push)
	if err != nil {
		t.Fatalf("Evaluate(push before approval): %v", err)
	}
	if decision.Action != ActionPendingApproval || decision.StageID != "review" {
		t.Fatalf("unexpected decision: %+v", decision)
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

	if err := rt.Reset(ctx, sess, "implement"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State after reset: %v", err)
	}
	if state.ActiveStage != "implement" || len(state.CompletedStages) != 0 {
		t.Fatalf("unexpected state after reset: %+v", state)
	}
	if len(state.Approvals) != 0 {
		t.Fatalf("expected approvals cleared, got %+v", state.Approvals)
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
