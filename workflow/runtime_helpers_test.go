package workflow

import "testing"

func TestWorkflowGateMetadataUsesSnapshotSchema(t *testing.T) {
	state := State{
		ActiveStage:     "review",
		CompletedStages: []string{"implement"},
	}
	state.markPendingApproval("review", "Approval required before push")

	metadata := workflowGateMetadata(
		Definition{Metadata: Metadata{Name: "push-process", Version: "v1"}},
		state,
		"approval",
		"stage boundary",
		false,
		"",
		map[string]any{"approval_requested_for": "review"},
	)

	if metadata["name"] != "push-process" {
		t.Fatalf("name = %#v, want %q", metadata["name"], "push-process")
	}
	if metadata["active_stage"] != "review" {
		t.Fatalf("active_stage = %#v, want %q", metadata["active_stage"], "review")
	}
	if _, ok := metadata["workflow_name"]; ok {
		t.Fatalf("unexpected legacy workflow_name key: %#v", metadata["workflow_name"])
	}
	if _, ok := metadata["stage_id"]; ok {
		t.Fatalf("unexpected legacy stage_id key: %#v", metadata["stage_id"])
	}
	if metadata["gate_kind"] != "approval" {
		t.Fatalf("gate_kind = %#v, want %q", metadata["gate_kind"], "approval")
	}
	pending, ok := metadata["pending_approval"].(map[string]any)
	if !ok {
		t.Fatalf("pending_approval type = %T, want map[string]any", metadata["pending_approval"])
	}
	if pending["required"] != true {
		t.Fatalf("pending_approval.required = %#v, want true", pending["required"])
	}
	if pending["stage_id"] != "review" {
		t.Fatalf("pending_approval.stage_id = %#v, want %q", pending["stage_id"], "review")
	}
}
