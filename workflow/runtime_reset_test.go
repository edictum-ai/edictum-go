package workflow

import (
	"context"
	"testing"
)

func TestRuntime_ResetRemainsDestructive(t *testing.T) {
	rt := mustRuntime(t, stageMoveWorkflowYAML)
	sess := newWorkflowSession(t, "wf-reset-destructive")
	ctx := context.Background()

	if err := seedState(ctx, rt, sess, stageMoveSeedState()); err != nil {
		t.Fatalf("seedState: %v", err)
	}

	events, err := rt.Reset(ctx, sess, "discover")
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Reset events len = %d, want 1", len(events))
	}
	if got, _ := events[0]["action"].(string); got != "workflow_state_updated" {
		t.Fatalf("Reset action = %q, want %q", got, "workflow_state_updated")
	}

	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State after Reset: %v", err)
	}
	if state.ActiveStage != "discover" {
		t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "discover")
	}
	if len(state.CompletedStages) != 0 {
		t.Fatalf("CompletedStages = %+v, want empty", state.CompletedStages)
	}
	if len(state.Approvals) != 0 {
		t.Fatalf("Approvals = %+v, want empty", state.Approvals)
	}
	if len(state.Evidence.StageCalls) != 0 {
		t.Fatalf("StageCalls = %+v, want empty", state.Evidence.StageCalls)
	}
	if len(state.Evidence.Reads) != 0 {
		t.Fatalf("Reads = %+v, want empty", state.Evidence.Reads)
	}
	if state.BlockedReason != "" {
		t.Fatalf("BlockedReason = %q, want empty", state.BlockedReason)
	}
	if state.PendingApproval.Required || state.PendingApproval.StageID != "" || state.PendingApproval.Message != "" {
		t.Fatalf("PendingApproval = %+v, want zero value", state.PendingApproval)
	}
	if state.LastRecordedEvidence != nil {
		t.Fatalf("LastRecordedEvidence = %+v, want nil", state.LastRecordedEvidence)
	}
	if state.LastBlockedAction != nil {
		t.Fatalf("LastBlockedAction = %+v, want nil", state.LastBlockedAction)
	}
}
