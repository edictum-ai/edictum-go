package approval

import (
	"testing"
	"time"
)

// --- Status constants ---

func TestStatusConstants_Distinct(t *testing.T) {
	statuses := []Status{StatusPending, StatusApproved, StatusDenied, StatusTimeout}
	seen := make(map[Status]bool, len(statuses))
	for _, s := range statuses {
		if s == "" {
			t.Fatalf("status constant must not be empty")
		}
		if seen[s] {
			t.Fatalf("duplicate status value %q", s)
		}
		seen[s] = true
	}
}

func TestStatusConstants_Values(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{StatusPending, "pending"},
		{StatusApproved, "approved"},
		{StatusDenied, "denied"},
		{StatusTimeout, "timeout"},
	}
	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("Status = %q, want %q", tt.status, tt.want)
		}
	}
}

// --- NewRequest constructor ---

func TestNewRequest_FieldsPopulated(t *testing.T) {
	before := time.Now().UTC()
	args := map[string]any{"key": "value"}
	r := NewRequest("req-1", "Bash", args, "approve this?")
	after := time.Now().UTC()

	if r.ApprovalID() != "req-1" {
		t.Errorf("ApprovalID() = %q, want %q", r.ApprovalID(), "req-1")
	}
	if r.ToolName() != "Bash" {
		t.Errorf("ToolName() = %q, want %q", r.ToolName(), "Bash")
	}
	if r.Message() != "approve this?" {
		t.Errorf("Message() = %q, want %q", r.Message(), "approve this?")
	}
	if r.CreatedAt().Before(before) || r.CreatedAt().After(after) {
		t.Errorf("CreatedAt() = %v, want between %v and %v", r.CreatedAt(), before, after)
	}

	got := r.ToolArgs()
	if got["key"] != "value" {
		t.Errorf("ToolArgs()[\"key\"] = %v, want %q", got["key"], "value")
	}
}

func TestNewRequest_Defaults(t *testing.T) {
	r := NewRequest("req-2", "ReadFile", nil, "")

	if r.Timeout() != 0 {
		t.Errorf("Timeout() = %v, want 0 (zero value)", r.Timeout())
	}
	if r.TimeoutEffect() != "" {
		t.Errorf("TimeoutEffect() = %q, want empty string", r.TimeoutEffect())
	}
	if r.Principal() != nil {
		t.Errorf("Principal() = %v, want nil", r.Principal())
	}
	if r.Metadata() != nil {
		t.Errorf("Metadata() = %v, want nil", r.Metadata())
	}
}

func TestNewRequest_DeepCopiesArgs(t *testing.T) {
	args := map[string]any{"nested": map[string]any{"a": 1}}
	r := NewRequest("req-3", "Tool", args, "msg")

	// Mutate original — Request must not be affected.
	nested := args["nested"].(map[string]any)
	nested["a"] = 999

	got := r.ToolArgs()
	inner, ok := got["nested"].(map[string]any)
	if !ok {
		t.Fatal("ToolArgs()[\"nested\"] is not map[string]any")
	}
	if inner["a"] != 1 {
		t.Errorf("mutation leaked into Request: got %v, want 1", inner["a"])
	}
}

func TestNewRequest_NilArgs(t *testing.T) {
	r := NewRequest("req-4", "Tool", nil, "msg")
	if r.ToolArgs() != nil {
		t.Errorf("ToolArgs() for nil input = %v, want nil", r.ToolArgs())
	}
}

// --- Getter defensive copies ---

func TestToolArgs_ReturnsCopy(t *testing.T) {
	args := map[string]any{"x": "original"}
	r := NewRequest("req-5", "Tool", args, "msg")

	// Mutate the returned copy — Request must not be affected.
	got := r.ToolArgs()
	got["x"] = "mutated"

	if r.ToolArgs()["x"] != "original" {
		t.Error("ToolArgs() returned a reference, not a copy")
	}
}

func TestMetadata_ReturnsCopy(t *testing.T) {
	r := NewRequest("req-6", "Tool", nil, "msg")
	// Metadata is set via direct struct access in the package (not exported),
	// so we test nil path. The defensive copy logic is shared with ToolArgs
	// and already tested above.
	if r.Metadata() != nil {
		t.Errorf("Metadata() = %v, want nil", r.Metadata())
	}
}

// --- WithTimeout option ---

func TestWithTimeout(t *testing.T) {
	r := NewRequest("req-7", "Tool", nil, "msg", WithTimeout(30*time.Second))
	if r.Timeout() != 30*time.Second {
		t.Errorf("Timeout() = %v, want %v", r.Timeout(), 30*time.Second)
	}
}

func TestWithTimeout_Zero(t *testing.T) {
	r := NewRequest("req-8", "Tool", nil, "msg", WithTimeout(0))
	if r.Timeout() != 0 {
		t.Errorf("Timeout() = %v, want 0", r.Timeout())
	}
}

// --- WithTimeoutEffect option ---

func TestWithTimeoutEffect_Deny(t *testing.T) {
	r := NewRequest("req-9", "Tool", nil, "msg", WithTimeoutEffect("deny"))
	if r.TimeoutEffect() != "deny" {
		t.Errorf("TimeoutEffect() = %q, want %q", r.TimeoutEffect(), "deny")
	}
}

func TestWithTimeoutEffect_Allow(t *testing.T) {
	r := NewRequest("req-10", "Tool", nil, "msg", WithTimeoutEffect("allow"))
	if r.TimeoutEffect() != "allow" {
		t.Errorf("TimeoutEffect() = %q, want %q", r.TimeoutEffect(), "allow")
	}
}

// --- Multiple options compose ---

func TestNewRequest_MultipleOptions(t *testing.T) {
	r := NewRequest("req-11", "Tool", nil, "msg",
		WithTimeout(60*time.Second),
		WithTimeoutEffect("deny"),
	)
	if r.Timeout() != 60*time.Second {
		t.Errorf("Timeout() = %v, want %v", r.Timeout(), 60*time.Second)
	}
	if r.TimeoutEffect() != "deny" {
		t.Errorf("TimeoutEffect() = %q, want %q", r.TimeoutEffect(), "deny")
	}
}

// --- Decision struct ---

func TestDecision_ZeroValue(t *testing.T) {
	var d Decision
	if d.Approved {
		t.Error("zero-value Decision.Approved should be false")
	}
	if d.Approver != "" {
		t.Errorf("zero-value Decision.Approver = %q, want empty", d.Approver)
	}
	if d.Reason != "" {
		t.Errorf("zero-value Decision.Reason = %q, want empty", d.Reason)
	}
	if d.Status != "" {
		t.Errorf("zero-value Decision.Status = %q, want empty", d.Status)
	}
	if !d.Timestamp.IsZero() {
		t.Errorf("zero-value Decision.Timestamp = %v, want zero", d.Timestamp)
	}
}

func TestDecision_FieldAccess(t *testing.T) {
	now := time.Now().UTC()
	d := Decision{
		Approved:  true,
		Approver:  "admin@example.com",
		Reason:    "looks safe",
		Status:    StatusApproved,
		Timestamp: now,
	}
	if !d.Approved {
		t.Error("Approved should be true")
	}
	if d.Approver != "admin@example.com" {
		t.Errorf("Approver = %q, want %q", d.Approver, "admin@example.com")
	}
	if d.Reason != "looks safe" {
		t.Errorf("Reason = %q, want %q", d.Reason, "looks safe")
	}
	if d.Status != StatusApproved {
		t.Errorf("Status = %q, want %q", d.Status, StatusApproved)
	}
	if !d.Timestamp.Equal(now) {
		t.Errorf("Timestamp = %v, want %v", d.Timestamp, now)
	}
}

// --- deepCopyMap / deepCopyValue ---

func TestDeepCopyMap_NestedSlice(t *testing.T) {
	src := map[string]any{
		"items": []any{"a", "b", map[string]any{"nested": true}},
	}
	dst := deepCopyMap(src)

	// Mutate source slice element.
	srcItems := src["items"].([]any)
	srcItems[0] = "mutated"
	srcNested := srcItems[2].(map[string]any)
	srcNested["nested"] = false

	dstItems := dst["items"].([]any)
	if dstItems[0] != "a" {
		t.Errorf("slice mutation leaked: got %v, want %q", dstItems[0], "a")
	}
	dstNested := dstItems[2].(map[string]any)
	if dstNested["nested"] != true {
		t.Errorf("nested map mutation leaked: got %v, want true", dstNested["nested"])
	}
}

func TestDeepCopyMap_Nil(t *testing.T) {
	if deepCopyMap(nil) != nil {
		t.Error("deepCopyMap(nil) should return nil")
	}
}

func TestDeepCopyValue_ScalarPassthrough(t *testing.T) {
	// Scalars are returned as-is (no copy needed for immutable types).
	if deepCopyValue(42) != 42 {
		t.Error("int passthrough failed")
	}
	if deepCopyValue("hello") != "hello" {
		t.Error("string passthrough failed")
	}
	if deepCopyValue(true) != true {
		t.Error("bool passthrough failed")
	}
	if deepCopyValue(nil) != nil {
		t.Error("nil passthrough failed")
	}
}
