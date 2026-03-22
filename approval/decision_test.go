package approval

import (
	"testing"
	"time"
)

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
