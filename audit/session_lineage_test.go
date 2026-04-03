package audit

import (
	"context"
	"encoding/json"
	"testing"
)

// --- Session lineage fields on Event ---

func TestEvent_SessionIDDefault(t *testing.T) {
	e := NewEvent()
	if e.SessionID != "" {
		t.Fatalf("SessionID = %q, want empty string", e.SessionID)
	}
	if e.ParentSessionID != "" {
		t.Fatalf("ParentSessionID = %q, want empty string", e.ParentSessionID)
	}
}

func TestEvent_SessionIDSet(t *testing.T) {
	e := NewEvent()
	e.SessionID = "sess-123"
	e.ParentSessionID = "sess-parent"

	if e.SessionID != "sess-123" {
		t.Fatalf("SessionID = %q, want %q", e.SessionID, "sess-123")
	}
	if e.ParentSessionID != "sess-parent" {
		t.Fatalf("ParentSessionID = %q, want %q", e.ParentSessionID, "sess-parent")
	}
}

func TestEvent_SessionIDJSONRoundTrip(t *testing.T) {
	e := NewEvent()
	e.SessionID = "sess-abc"
	e.ParentSessionID = "sess-parent-abc"

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.SessionID != "sess-abc" {
		t.Fatalf("decoded SessionID = %q, want %q", decoded.SessionID, "sess-abc")
	}
	if decoded.ParentSessionID != "sess-parent-abc" {
		t.Fatalf("decoded ParentSessionID = %q, want %q", decoded.ParentSessionID, "sess-parent-abc")
	}
}

func TestEvent_SessionIDOmittedWhenEmpty(t *testing.T) {
	e := NewEvent()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := raw["session_id"]; ok {
		t.Fatal("session_id should be omitted from JSON when empty")
	}
	if _, ok := raw["parent_session_id"]; ok {
		t.Fatal("parent_session_id should be omitted from JSON when empty")
	}
}

// --- ActionWorkflowStateUpdated constant ---

func TestActionWorkflowStateUpdated_Value(t *testing.T) {
	if string(ActionWorkflowStateUpdated) != "workflow_state_updated" {
		t.Fatalf("ActionWorkflowStateUpdated = %q, want %q",
			ActionWorkflowStateUpdated, "workflow_state_updated")
	}
}

func TestActionWorkflowStateUpdated_DistinctFromExisting(t *testing.T) {
	workflowActions := []Action{
		ActionWorkflowStageAdvanced,
		ActionWorkflowCompleted,
		ActionWorkflowStateUpdated,
	}
	seen := make(map[Action]bool, len(workflowActions))
	for _, a := range workflowActions {
		if seen[a] {
			t.Fatalf("duplicate workflow action %q", a)
		}
		seen[a] = true
	}
}

func TestActionWorkflowStateUpdated_NotInAllActions(t *testing.T) {
	// Workflow actions are intentionally excluded from AllActions()
	// to preserve the canonical parity set.
	for _, a := range AllActions() {
		if a == ActionWorkflowStateUpdated {
			t.Fatal("ActionWorkflowStateUpdated should not be in AllActions()")
		}
	}
}

// --- Session lineage preserved through CompositeSink deep copy ---

func TestCompositeSink_SessionIDPreserved(t *testing.T) {
	capture := &captureSink{}
	comp := NewCompositeSink(capture)

	e := NewEvent()
	e.SessionID = "sess-composite"
	e.ParentSessionID = "sess-parent-composite"
	if err := comp.Emit(context.Background(), &e); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if capture.last.SessionID != "sess-composite" {
		t.Fatalf("SessionID = %q, want %q", capture.last.SessionID, "sess-composite")
	}
	if capture.last.ParentSessionID != "sess-parent-composite" {
		t.Fatalf("ParentSessionID = %q, want %q", capture.last.ParentSessionID, "sess-parent-composite")
	}
}

// --- Session lineage preserved through CollectingSink ---

func TestCollectingSink_SessionIDPreserved(t *testing.T) {
	sink := NewCollectingSink(10)
	ctx := context.Background()

	e := NewEvent()
	e.SessionID = "sess-collecting"
	e.ParentSessionID = "sess-parent-collecting"
	if err := sink.Emit(ctx, &e); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}
	if events[0].SessionID != "sess-collecting" {
		t.Fatalf("SessionID = %q, want %q", events[0].SessionID, "sess-collecting")
	}
	if events[0].ParentSessionID != "sess-parent-collecting" {
		t.Fatalf("ParentSessionID = %q, want %q", events[0].ParentSessionID, "sess-parent-collecting")
	}
}
