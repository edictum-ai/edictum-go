package approval

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func TestMemoryBackend_RequestApprovalContextCancelWhenQueueFull(t *testing.T) {
	backend := NewMemoryBackend()

	for i := 0; i < cap(backend.requestCh); i++ {
		if _, err := backend.RequestApproval(context.Background(), "Bash", nil, "review"); err != nil {
			t.Fatalf("RequestApproval fill %d: %v", i, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := backend.RequestApproval(ctx, "Bash", nil, "review")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RequestApproval error = %v, want context deadline exceeded", err)
	}
	if len(backend.requests) != cap(backend.requestCh) {
		t.Fatalf("requests len = %d, want %d", len(backend.requests), cap(backend.requestCh))
	}
}

func TestMemoryBackend_PollApprovalStatusUnknownID(t *testing.T) {
	backend := NewMemoryBackend()

	_, err := backend.PollApprovalStatus(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), "approval not found") {
		t.Fatalf("PollApprovalStatus error = %v, want approval not found", err)
	}
}

func TestMemoryBackend_RequestApprovalContextCancelRemovesRacedDecision(t *testing.T) {
	backend := NewMemoryBackend()

	for i := 0; i < cap(backend.requestCh); i++ {
		if _, err := backend.RequestApproval(context.Background(), "Bash", nil, "review"); err != nil {
			t.Fatalf("RequestApproval fill %d: %v", i, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := backend.RequestApproval(ctx, "Bash", nil, "review")
		errCh <- err
	}()

	approvalID := fmt.Sprintf("approval-%d", cap(backend.requestCh)+1)
	deadline := time.Now().Add(time.Second)
	for {
		backend.mu.Lock()
		_, hasRequest := backend.requests[approvalID]
		_, hasWaiter := backend.waiters[approvalID]
		backend.mu.Unlock()
		if hasRequest && hasWaiter {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s registration", approvalID)
		}
		time.Sleep(time.Millisecond)
	}

	if err := backend.Approve(approvalID, "reviewer@example.com", "approved"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RequestApproval error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RequestApproval to return")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if _, ok := backend.requests[approvalID]; ok {
		t.Fatalf("requests[%s] still present after cancellation", approvalID)
	}
	if _, ok := backend.waiters[approvalID]; ok {
		t.Fatalf("waiters[%s] still present after cancellation", approvalID)
	}
	if _, ok := backend.decisions[approvalID]; ok {
		t.Fatalf("decisions[%s] still present after cancellation", approvalID)
	}
}

func TestMemoryBackend_DoubleDecisionRejected(t *testing.T) {
	backend := NewMemoryBackend()

	req, err := backend.RequestApproval(context.Background(), "Bash", nil, "review")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if err := backend.Approve(req.ApprovalID(), "reviewer@example.com", "approved"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := backend.Deny(req.ApprovalID(), "reviewer@example.com", "denied"); err == nil || !strings.Contains(err.Error(), "already decided") {
		t.Fatalf("Deny error = %v, want already decided", err)
	}
}
