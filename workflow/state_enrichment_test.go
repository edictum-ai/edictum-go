package workflow

import (
	"encoding/json"
	"testing"
)

// --- Enriched State fields ---

func TestState_BlockedReasonDefault(t *testing.T) {
	s := State{}
	s.ensureMaps()
	if s.BlockedReason != "" {
		t.Fatalf("BlockedReason = %q, want empty string", s.BlockedReason)
	}
}

func TestState_BlockedReasonSet(t *testing.T) {
	s := State{BlockedReason: "Tool not allowed in this stage"}
	if s.BlockedReason != "Tool not allowed in this stage" {
		t.Fatalf("BlockedReason = %q, want %q", s.BlockedReason, "Tool not allowed in this stage")
	}
}

func TestState_PendingApprovalDefault(t *testing.T) {
	s := State{}
	s.ensureMaps()
	if s.PendingApproval != nil {
		t.Fatalf("PendingApproval = %+v, want nil", s.PendingApproval)
	}
}

func TestState_PendingApprovalSet(t *testing.T) {
	s := State{
		PendingApproval: &PendingApproval{
			Required: true,
			StageID:  "local-review",
			Message:  "Approve after reviewing the diff",
		},
	}
	if !s.PendingApproval.Required {
		t.Fatal("PendingApproval.Required should be true")
	}
	if s.PendingApproval.StageID != "local-review" {
		t.Fatalf("PendingApproval.StageID = %q, want %q", s.PendingApproval.StageID, "local-review")
	}
	if s.PendingApproval.Message != "Approve after reviewing the diff" {
		t.Fatalf("PendingApproval.Message = %q", s.PendingApproval.Message)
	}
}

func TestState_LastBlockedActionDefault(t *testing.T) {
	s := State{}
	s.ensureMaps()
	if s.LastBlockedAction != nil {
		t.Fatalf("LastBlockedAction = %+v, want nil", s.LastBlockedAction)
	}
}

func TestState_LastBlockedActionSet(t *testing.T) {
	s := State{
		LastBlockedAction: &BlockedAction{
			Tool:    "Bash",
			Summary: "git push origin main",
			Message: "Push to a branch, not main",
		},
	}
	if s.LastBlockedAction.Tool != "Bash" {
		t.Fatalf("LastBlockedAction.Tool = %q, want %q", s.LastBlockedAction.Tool, "Bash")
	}
	if s.LastBlockedAction.Summary != "git push origin main" {
		t.Fatalf("LastBlockedAction.Summary = %q", s.LastBlockedAction.Summary)
	}
	if s.LastBlockedAction.Message != "Push to a branch, not main" {
		t.Fatalf("LastBlockedAction.Message = %q", s.LastBlockedAction.Message)
	}
}

// --- JSON round-trip ---

func TestState_EnrichedFieldsJSONRoundTrip(t *testing.T) {
	original := State{
		SessionID:       "sess-rt",
		ActiveStage:     "implement",
		CompletedStages: []string{"read-context"},
		Approvals:       map[string]string{},
		Evidence:        Evidence{Reads: []string{}, StageCalls: map[string][]string{}},
		BlockedReason:   "Only review-safe commands allowed",
		PendingApproval: &PendingApproval{
			Required: true,
			StageID:  "local-review",
			Message:  "Approve after review",
		},
		LastBlockedAction: &BlockedAction{
			Tool:      "Bash",
			Summary:   "git push",
			Message:   "Push not allowed yet",
			Timestamp: "2026-04-01T09:13:04Z",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded State
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.BlockedReason != original.BlockedReason {
		t.Fatalf("BlockedReason = %q, want %q", decoded.BlockedReason, original.BlockedReason)
	}
	if decoded.PendingApproval == nil {
		t.Fatal("PendingApproval should not be nil after decode")
	}
	if !decoded.PendingApproval.Required {
		t.Fatal("PendingApproval.Required should be true")
	}
	if decoded.PendingApproval.StageID != "local-review" {
		t.Fatalf("PendingApproval.StageID = %q", decoded.PendingApproval.StageID)
	}
	if decoded.LastBlockedAction == nil {
		t.Fatal("LastBlockedAction should not be nil after decode")
	}
	if decoded.LastBlockedAction.Tool != "Bash" {
		t.Fatalf("LastBlockedAction.Tool = %q", decoded.LastBlockedAction.Tool)
	}
	if decoded.LastBlockedAction.Timestamp != "2026-04-01T09:13:04Z" {
		t.Fatalf("LastBlockedAction.Timestamp = %q", decoded.LastBlockedAction.Timestamp)
	}
}

func TestState_EnrichedFieldsOmittedWhenEmpty(t *testing.T) {
	s := State{
		SessionID:       "sess-empty",
		ActiveStage:     "read-context",
		CompletedStages: []string{},
		Approvals:       map[string]string{},
		Evidence:        Evidence{Reads: []string{}, StageCalls: map[string][]string{}},
	}

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := raw["blocked_reason"]; ok {
		t.Fatal("blocked_reason should be omitted when empty")
	}
	if _, ok := raw["pending_approval"]; ok {
		t.Fatal("pending_approval should be omitted when nil")
	}
	if _, ok := raw["last_blocked_action"]; ok {
		t.Fatal("last_blocked_action should be omitted when nil")
	}
}

// --- PendingApproval and BlockedAction types ---

func TestPendingApproval_JSONTags(t *testing.T) {
	pa := PendingApproval{
		Required: true,
		StageID:  "review",
		Message:  "please approve",
	}
	data, err := json.Marshal(pa)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if raw["required"] != true {
		t.Fatal("expected required=true in JSON")
	}
	if raw["stage_id"] != "review" {
		t.Fatalf("expected stage_id=review, got %v", raw["stage_id"])
	}
}

func TestBlockedAction_JSONTags(t *testing.T) {
	ba := BlockedAction{
		Tool:    "Bash",
		Summary: "rm -rf /",
		Message: "blocked by sandbox",
	}
	data, err := json.Marshal(ba)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if raw["tool"] != "Bash" {
		t.Fatalf("expected tool=Bash, got %v", raw["tool"])
	}
	if raw["summary"] != "rm -rf /" {
		t.Fatalf("expected summary, got %v", raw["summary"])
	}
}
