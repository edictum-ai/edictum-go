package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryBackend_ApproveFlow(t *testing.T) {
	backend := NewMemoryBackend()

	req, err := backend.RequestApproval(
		context.Background(),
		"Bash",
		map[string]any{"command": "git push origin feature"},
		"review push",
		WithSessionID("session-123"),
	)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	waited, err := backend.WaitForRequest(context.Background())
	if err != nil {
		t.Fatalf("WaitForRequest: %v", err)
	}
	if waited.ApprovalID() != req.ApprovalID() {
		t.Fatalf("WaitForRequest ApprovalID = %q, want %q", waited.ApprovalID(), req.ApprovalID())
	}
	if waited.SessionID() != "session-123" {
		t.Fatalf("WaitForRequest SessionID = %q, want %q", waited.SessionID(), "session-123")
	}

	if err := backend.Approve(req.ApprovalID(), "reviewer@example.com", "looks good"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	decision, err := backend.PollApprovalStatus(context.Background(), req.ApprovalID())
	if err != nil {
		t.Fatalf("PollApprovalStatus: %v", err)
	}
	if !decision.Approved {
		t.Fatal("Approved = false, want true")
	}
	if decision.Status != StatusApproved {
		t.Fatalf("Status = %q, want %q", decision.Status, StatusApproved)
	}
	if decision.Approver != "reviewer@example.com" {
		t.Fatalf("Approver = %q, want %q", decision.Approver, "reviewer@example.com")
	}
	if decision.Reason != "looks good" {
		t.Fatalf("Reason = %q, want %q", decision.Reason, "looks good")
	}
}

func TestMemoryBackend_DenyFlow(t *testing.T) {
	backend := NewMemoryBackend()

	req, err := backend.RequestApproval(context.Background(), "Bash", nil, "review")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if err := backend.Deny(req.ApprovalID(), "security@example.com", "too risky"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	decision, err := backend.PollApprovalStatus(context.Background(), req.ApprovalID())
	if err != nil {
		t.Fatalf("PollApprovalStatus: %v", err)
	}
	if decision.Approved {
		t.Fatal("Approved = true, want false")
	}
	if decision.Status != StatusDenied {
		t.Fatalf("Status = %q, want %q", decision.Status, StatusDenied)
	}
	if decision.Approver != "security@example.com" {
		t.Fatalf("Approver = %q, want %q", decision.Approver, "security@example.com")
	}
	if decision.Reason != "too risky" {
		t.Fatalf("Reason = %q, want %q", decision.Reason, "too risky")
	}
}

func TestMemoryBackend_PollApprovalStatusContextCancel(t *testing.T) {
	backend := NewMemoryBackend()

	req, err := backend.RequestApproval(context.Background(), "Bash", nil, "review")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	decision, err := backend.PollApprovalStatus(ctx, req.ApprovalID())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PollApprovalStatus error = %v, want context deadline exceeded", err)
	}
	if decision.Status != StatusTimeout {
		t.Fatalf("Status = %q, want %q", decision.Status, StatusTimeout)
	}
}
