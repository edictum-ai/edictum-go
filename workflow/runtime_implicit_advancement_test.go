package workflow

import (
	"context"
	"testing"
)

const noExitApprovalAdvanceWorkflowYAML = `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: no-exit-approval-advance
stages:
  - id: implement
    tools: [Read]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Approval required before ship
  - id: ship
    entry:
      - condition: approval("review")
    tools: [Edit]
`

const noExitApprovalEntryGuardWorkflowYAML = `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: no-exit-approval-entry-guard
stages:
  - id: implement
    tools: [Read]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Approval required before ship
  - id: ship
    entry:
      - condition: approval("review")
      - condition: file_read("release/notes.md")
        message: Read release notes before ship
    tools: [Edit]
`

func TestRuntime_NoExitStageOnlyAdvancesForLegitimateNextStageWork(t *testing.T) {
	ctx := context.Background()
	rt := mustRuntime(t, noExitApprovalAdvanceWorkflowYAML)

	t.Run("future stage work pauses at approval", func(t *testing.T) {
		sess := newWorkflowSession(t, "wf-no-exit-approval-next-work")

		edit := makeCall(t, "Edit", map[string]any{"path": "src/app.ts"})
		decision, err := rt.Evaluate(ctx, sess, edit)
		if err != nil {
			t.Fatalf("Evaluate(edit): %v", err)
		}
		if decision.Action != ActionPendingApproval || decision.StageID != "review" {
			t.Fatalf("unexpected edit decision: %+v", decision)
		}

		state, err := rt.State(ctx, sess)
		if err != nil {
			t.Fatalf("State after edit: %v", err)
		}
		if state.ActiveStage != "review" {
			t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "review")
		}
		if !state.PendingApproval.Required || state.PendingApproval.StageID != "review" {
			t.Fatalf("PendingApproval = %+v, want review approval", state.PendingApproval)
		}
	})

	t.Run("unrelated work stays in current stage", func(t *testing.T) {
		sess := newWorkflowSession(t, "wf-no-exit-approval-unrelated-work")

		bash := makeCall(t, "Bash", map[string]any{"command": "go test ./..."})
		decision, err := rt.Evaluate(ctx, sess, bash)
		if err != nil {
			t.Fatalf("Evaluate(bash): %v", err)
		}
		if decision.Action != ActionBlock {
			t.Fatalf("unexpected bash decision: %+v", decision)
		}
		if decision.Reason != "Tool is not allowed in this workflow stage" {
			t.Fatalf("Reason = %q, want tool-not-allowed", decision.Reason)
		}

		state, err := rt.State(ctx, sess)
		if err != nil {
			t.Fatalf("State after bash: %v", err)
		}
		if state.ActiveStage != "implement" {
			t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "implement")
		}
		if len(state.CompletedStages) != 0 {
			t.Fatalf("CompletedStages = %+v, want empty", state.CompletedStages)
		}
		if state.PendingApproval.Required {
			t.Fatalf("PendingApproval = %+v, want zero value", state.PendingApproval)
		}
	})
}

func TestRuntime_NoExitStageRequiresDownstreamEntryReadinessBeforeAdvance(t *testing.T) {
	ctx := context.Background()
	rt := mustRuntime(t, noExitApprovalEntryGuardWorkflowYAML)

	t.Run("missing downstream evidence stays in current stage", func(t *testing.T) {
		sess := newWorkflowSession(t, "wf-no-exit-entry-guard-missing")

		edit := makeCall(t, "Edit", map[string]any{"path": "src/app.ts"})
		decision, err := rt.Evaluate(ctx, sess, edit)
		if err != nil {
			t.Fatalf("Evaluate(edit): %v", err)
		}
		if decision.Action != ActionBlock {
			t.Fatalf("unexpected edit decision: %+v", decision)
		}
		if decision.Reason != "Tool is not allowed in this workflow stage" {
			t.Fatalf("Reason = %q, want tool-not-allowed", decision.Reason)
		}

		state, err := rt.State(ctx, sess)
		if err != nil {
			t.Fatalf("State after edit: %v", err)
		}
		if state.ActiveStage != "implement" {
			t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "implement")
		}
		if len(state.CompletedStages) != 0 {
			t.Fatalf("CompletedStages = %+v, want empty", state.CompletedStages)
		}
	})

	t.Run("ready downstream evidence advances into approval", func(t *testing.T) {
		sess := newWorkflowSession(t, "wf-no-exit-entry-guard-ready")

		read := makeCall(t, "Read", map[string]any{"path": "release/notes.md"})
		decision, err := rt.Evaluate(ctx, sess, read)
		if err != nil {
			t.Fatalf("Evaluate(read): %v", err)
		}
		if decision.Action != ActionAllow || decision.StageID != "implement" {
			t.Fatalf("unexpected read decision: %+v", decision)
		}
		if _, err := rt.RecordResult(ctx, sess, decision.StageID, read); err != nil {
			t.Fatalf("RecordResult(read): %v", err)
		}

		edit := makeCall(t, "Edit", map[string]any{"path": "src/app.ts"})
		decision, err = rt.Evaluate(ctx, sess, edit)
		if err != nil {
			t.Fatalf("Evaluate(edit): %v", err)
		}
		if decision.Action != ActionPendingApproval || decision.StageID != "review" {
			t.Fatalf("unexpected edit decision: %+v", decision)
		}

		state, err := rt.State(ctx, sess)
		if err != nil {
			t.Fatalf("State after edit: %v", err)
		}
		if state.ActiveStage != "review" {
			t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "review")
		}
		if len(state.CompletedStages) != 1 || state.CompletedStages[0] != "implement" {
			t.Fatalf("CompletedStages = %+v, want [implement]", state.CompletedStages)
		}
		if !state.PendingApproval.Required || state.PendingApproval.StageID != "review" {
			t.Fatalf("PendingApproval = %+v, want review approval", state.PendingApproval)
		}
	})
}
