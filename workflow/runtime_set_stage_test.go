package workflow

import (
	"context"
	"testing"
)

func TestRuntime_SetStageMovesWithoutClearingEvidenceOrApprovals(t *testing.T) {
	rt := mustRuntime(t, stageMoveWorkflowYAML)
	sess := newWorkflowSession(t, "wf-set-stage")
	ctx := context.Background()

	if err := seedState(ctx, rt, sess, stageMoveSeedState()); err != nil {
		t.Fatalf("seedState: %v", err)
	}

	events, err := rt.SetStage(ctx, sess, "implement")
	if err != nil {
		t.Fatalf("SetStage: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("SetStage events len = %d, want 1", len(events))
	}
	if got, _ := events[0]["action"].(string); got != "workflow_state_updated" {
		t.Fatalf("SetStage action = %q, want %q", got, "workflow_state_updated")
	}
	workflowData, ok := events[0]["workflow"].(map[string]any)
	if !ok {
		t.Fatalf("SetStage workflow payload type = %T, want map[string]any", events[0]["workflow"])
	}
	if workflowData["active_stage"] != "implement" {
		t.Fatalf("SetStage active_stage = %#v, want %q", workflowData["active_stage"], "implement")
	}
	completed, ok := workflowData["completed_stages"].([]any)
	if !ok {
		t.Fatalf("SetStage completed_stages type = %T, want []any", workflowData["completed_stages"])
	}
	if len(completed) != 1 || completed[0] != "discover" {
		t.Fatalf("SetStage completed_stages = %#v, want [discover]", completed)
	}
	pending, ok := workflowData["pending_approval"].(map[string]any)
	if !ok {
		t.Fatalf("SetStage pending_approval type = %T, want map[string]any", workflowData["pending_approval"])
	}
	if pending["required"] != false {
		t.Fatalf("SetStage pending_approval.required = %#v, want false", pending["required"])
	}
	if blocked, ok := workflowData["blocked_reason"]; !ok || blocked != nil {
		t.Fatalf("SetStage blocked_reason = %#v, want nil", blocked)
	}
	if _, ok := workflowData["last_blocked_action"]; ok {
		t.Fatalf("SetStage last_blocked_action = %#v, want omitted", workflowData["last_blocked_action"])
	}
	if _, ok := workflowData["last_recorded_evidence"]; !ok {
		t.Fatal("expected SetStage event to preserve last_recorded_evidence")
	}

	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State after SetStage: %v", err)
	}
	if state.ActiveStage != "implement" {
		t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "implement")
	}
	if len(state.CompletedStages) != 1 || state.CompletedStages[0] != "discover" {
		t.Fatalf("CompletedStages = %+v, want [discover]", state.CompletedStages)
	}
	if got := state.Approvals["review"]; got != approvedStatus {
		t.Fatalf("approval[review] = %q, want %q", got, approvedStatus)
	}
	if got := state.Evidence.StageCalls["push"]; len(got) != 1 || got[0] != "git push origin feature-branch" {
		t.Fatalf("stage_calls[push] = %+v, want [git push origin feature-branch]", got)
	}
	if len(state.Evidence.Reads) != 1 || state.Evidence.Reads[0] != "specs/008.md" {
		t.Fatalf("reads = %+v, want [specs/008.md]", state.Evidence.Reads)
	}
	if state.BlockedReason != "" {
		t.Fatalf("BlockedReason = %q, want empty", state.BlockedReason)
	}
	if state.PendingApproval.Required || state.PendingApproval.StageID != "" || state.PendingApproval.Message != "" {
		t.Fatalf("PendingApproval = %+v, want zero value", state.PendingApproval)
	}
	if state.LastBlockedAction != nil {
		t.Fatalf("LastBlockedAction = %+v, want nil", state.LastBlockedAction)
	}
	if state.LastRecordedEvidence == nil {
		t.Fatal("expected LastRecordedEvidence to be preserved")
	}
	if state.LastRecordedEvidence.Tool != "Bash" {
		t.Fatalf("LastRecordedEvidence.Tool = %q, want %q", state.LastRecordedEvidence.Tool, "Bash")
	}
	if state.LastRecordedEvidence.Summary != "git" {
		t.Fatalf("LastRecordedEvidence.Summary = %q, want %q", state.LastRecordedEvidence.Summary, "git")
	}
}

func TestRuntime_SetStageHydratesTargetStageApproval(t *testing.T) {
	rt := mustRuntime(t, stageMoveWorkflowYAML)
	sess := newWorkflowSession(t, "wf-set-stage-review")
	ctx := context.Background()

	events, err := rt.SetStage(ctx, sess, "review")
	if err != nil {
		t.Fatalf("SetStage(review): %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("SetStage(review) events len = %d, want 1", len(events))
	}
	workflowData, ok := events[0]["workflow"].(map[string]any)
	if !ok {
		t.Fatalf("SetStage(review) workflow payload type = %T, want map[string]any", events[0]["workflow"])
	}
	if workflowData["active_stage"] != "review" {
		t.Fatalf("SetStage(review) active_stage = %#v, want %q", workflowData["active_stage"], "review")
	}
	pending, ok := workflowData["pending_approval"].(map[string]any)
	if !ok {
		t.Fatalf("SetStage(review) pending_approval type = %T, want map[string]any", workflowData["pending_approval"])
	}
	if pending["required"] != true {
		t.Fatalf("SetStage(review) pending_approval.required = %#v, want true", pending["required"])
	}
	if pending["stage_id"] != "review" {
		t.Fatalf("SetStage(review) pending_approval.stage_id = %#v, want %q", pending["stage_id"], "review")
	}
	if pending["message"] != "Approval required before push" {
		t.Fatalf("SetStage(review) pending_approval.message = %#v, want %q", pending["message"], "Approval required before push")
	}

	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State after SetStage(review): %v", err)
	}
	if state.ActiveStage != "review" {
		t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "review")
	}
	if !state.PendingApproval.Required {
		t.Fatal("expected PendingApproval.Required after SetStage(review)")
	}
	if state.PendingApproval.StageID != "review" {
		t.Fatalf("PendingApproval.StageID = %q, want %q", state.PendingApproval.StageID, "review")
	}
	if state.PendingApproval.Message != "Approval required before push" {
		t.Fatalf("PendingApproval.Message = %q, want %q", state.PendingApproval.Message, "Approval required before push")
	}
}

func TestRuntime_SetStageToApprovedBoundaryStageDoesNotSetPendingApproval(t *testing.T) {
	rt := mustRuntime(t, stageMoveWorkflowYAML)
	sess := newWorkflowSession(t, "wf-set-stage-already-approved")
	ctx := context.Background()

	if err := seedState(ctx, rt, sess, stageMoveSeedState()); err != nil {
		t.Fatalf("seedState: %v", err)
	}

	events, err := rt.SetStage(ctx, sess, "review")
	if err != nil {
		t.Fatalf("SetStage(review): %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("SetStage(review) events len = %d, want 1", len(events))
	}
	workflowData, ok := events[0]["workflow"].(map[string]any)
	if !ok {
		t.Fatalf("SetStage(review) workflow payload type = %T, want map[string]any", events[0]["workflow"])
	}
	pending, ok := workflowData["pending_approval"].(map[string]any)
	if !ok {
		t.Fatalf("SetStage(review) pending_approval type = %T, want map[string]any", workflowData["pending_approval"])
	}
	if pending["required"] != false {
		t.Fatalf("SetStage(review) pending_approval.required = %#v, want false", pending["required"])
	}
	if _, ok := pending["stage_id"]; ok {
		t.Fatalf("SetStage(review) pending_approval.stage_id = %#v, want omitted", pending["stage_id"])
	}
	if _, ok := pending["message"]; ok {
		t.Fatalf("SetStage(review) pending_approval.message = %#v, want omitted", pending["message"])
	}

	state, err := rt.State(ctx, sess)
	if err != nil {
		t.Fatalf("State after SetStage(review): %v", err)
	}
	if state.PendingApproval.Required || state.PendingApproval.StageID != "" || state.PendingApproval.Message != "" {
		t.Fatalf("PendingApproval = %+v, want zero value", state.PendingApproval)
	}
}

func TestRuntime_SetStageRejectsUnknownStage(t *testing.T) {
	rt := mustRuntime(t, stageMoveWorkflowYAML)
	sess := newWorkflowSession(t, "wf-set-stage-unknown")

	if _, err := rt.SetStage(context.Background(), sess, "missing"); err == nil {
		t.Fatal("expected SetStage to reject unknown stage")
	}
}

func TestRuntime_SetStageAllowsEvaluationFromNewActiveStage(t *testing.T) {
	rt := mustRuntime(t, stageMoveWorkflowYAML)
	sess := newWorkflowSession(t, "wf-set-stage-evaluate")
	ctx := context.Background()

	if _, err := rt.SetStage(ctx, sess, "implement"); err != nil {
		t.Fatalf("SetStage: %v", err)
	}

	edit := makeCall(t, "Edit", map[string]any{"path": "src/app.ts"})
	decision, err := rt.Evaluate(ctx, sess, edit)
	if err != nil {
		t.Fatalf("Evaluate(edit): %v", err)
	}
	if decision.Action != ActionAllow || decision.StageID != "implement" {
		t.Fatalf("unexpected edit decision after SetStage: %+v", decision)
	}
}
