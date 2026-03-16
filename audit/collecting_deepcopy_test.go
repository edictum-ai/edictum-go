package audit

import (
	"context"
	"testing"
)

// TestCollectingSink_DeepCopyOnRetrieval proves that mutating events
// returned by Events(), Last(), Filter(), and SinceMark() does NOT
// corrupt the internal buffer.
func TestCollectingSink_DeepCopyOnRetrieval(t *testing.T) {
	sink := NewCollectingSink(100)
	ctx := context.Background()

	e := NewEvent()
	e.ToolName = "Bash"
	e.Action = ActionCallAllowed
	e.ToolArgs = map[string]any{
		"command": "ls",
		"nested":  map[string]any{"key": "original"},
	}
	if err := sink.Emit(ctx, &e); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// --- Events() ---
	events := sink.Events()
	events[0].ToolArgs["nested"].(map[string]any)["key"] = "mutated-events"
	events[0].ToolName = "CORRUPTED"

	fresh := sink.Events()
	if fresh[0].ToolName != "Bash" {
		t.Errorf("Events() ToolName corrupted: got %q", fresh[0].ToolName)
	}
	nested := fresh[0].ToolArgs["nested"].(map[string]any)
	if nested["key"] != "original" {
		t.Errorf("Events() nested map corrupted: got %v", nested["key"])
	}

	// --- Last() ---
	last, err := sink.Last()
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	last.ToolArgs["nested"].(map[string]any)["key"] = "mutated-last"

	last2, _ := sink.Last()
	if last2.ToolArgs["nested"].(map[string]any)["key"] != "original" {
		t.Error("Last() nested map corrupted")
	}

	// --- Filter() ---
	filtered := sink.Filter(ActionCallAllowed)
	filtered[0].ToolArgs["nested"].(map[string]any)["key"] = "mutated-filter"

	filtered2 := sink.Filter(ActionCallAllowed)
	if filtered2[0].ToolArgs["nested"].(map[string]any)["key"] != "original" {
		t.Error("Filter() nested map corrupted")
	}

	// --- SinceMark() ---
	// Mark was 0 (before emit), so SinceMark(0) returns all events.
	since, err := sink.SinceMark(0)
	if err != nil {
		t.Fatalf("SinceMark: %v", err)
	}
	since[0].ToolArgs["nested"].(map[string]any)["key"] = "mutated-since"

	since2, _ := sink.SinceMark(0)
	if since2[0].ToolArgs["nested"].(map[string]any)["key"] != "original" {
		t.Error("SinceMark() nested map corrupted")
	}
}
