package guard

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func TestDeepCopyRecords_DeepCopiesNestedValues(t *testing.T) {
	original := []map[string]any{{
		"nested": map[string]any{
			"value": "original",
			"list":  []any{map[string]any{"leaf": "kept"}},
		},
	}}

	copied := deepCopyRecords(original)
	copied[0]["nested"].(map[string]any)["value"] = "mutated"
	copied[0]["nested"].(map[string]any)["list"].([]any)[0].(map[string]any)["leaf"] = "changed"

	nested := original[0]["nested"].(map[string]any)
	if got := nested["value"]; got != "original" {
		t.Fatalf("nested map mutated original: got %v", got)
	}
	list := nested["list"].([]any)
	if got := list[0].(map[string]any)["leaf"]; got != "kept" {
		t.Fatalf("nested slice mutated original: got %v", got)
	}
}

func TestEmitPreAuditUsesSessionID(t *testing.T) {
	ctx := context.Background()
	g := New()
	sess, err := session.New("session-123", session.NewMemoryBackend())
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	env2, err := toolcall.CreateToolCall(ctx, toolcall.CreateToolCallOptions{
		ToolName: "Read",
		RunID:    "run-456",
		Metadata: map[string]any{parentSessionIDMetadataKey: "parent-789"},
	})
	if err != nil {
		t.Fatalf("CreateToolCall: %v", err)
	}

	g.emitPreAudit(ctx, env2, sess, audit.ActionCallAllowed, pipeline.PreDecision{}, "enforce", "policy")

	events := g.LocalSink().Events()
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if events[0].RunID != "run-456" {
		t.Fatalf("RunID = %q, want %q", events[0].RunID, "run-456")
	}
	if events[0].SessionID != "session-123" {
		t.Fatalf("SessionID = %q, want %q", events[0].SessionID, "session-123")
	}
	if events[0].ParentSessionID != "parent-789" {
		t.Fatalf("ParentSessionID = %q, want %q", events[0].ParentSessionID, "parent-789")
	}
}

func TestEmitWorkflowEventsUsesSessionID(t *testing.T) {
	ctx := context.Background()
	g := New()
	sess, err := session.New("session-123", session.NewMemoryBackend())
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	env2, err := toolcall.CreateToolCall(ctx, toolcall.CreateToolCallOptions{
		ToolName: "Bash",
		RunID:    "run-456",
		Metadata: map[string]any{parentSessionIDMetadataKey: "parent-789"},
	})
	if err != nil {
		t.Fatalf("CreateToolCall: %v", err)
	}

	g.emitWorkflowEvents(ctx, env2, sess, []map[string]any{{
		"action": string(audit.ActionWorkflowStageAdvanced),
		"workflow": map[string]any{
			"name":             "push-process",
			"active_stage":     "review",
			"completed_stages": []any{"implement"},
			"pending_approval": map[string]any{"required": false},
		},
	}}, "enforce", "policy")

	events := g.LocalSink().Events()
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if events[0].RunID != "run-456" {
		t.Fatalf("RunID = %q, want %q", events[0].RunID, "run-456")
	}
	if events[0].SessionID != "session-123" {
		t.Fatalf("SessionID = %q, want %q", events[0].SessionID, "session-123")
	}
	if events[0].ParentSessionID != "parent-789" {
		t.Fatalf("ParentSessionID = %q, want %q", events[0].ParentSessionID, "parent-789")
	}
}
