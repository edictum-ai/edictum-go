package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edictum-ai/edictum-go/approval"
)

// --- 10.14: Approval polling ---

func TestApprovalPolling(t *testing.T) {
	var pollCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/approvals" {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "approval-123"})
			return
		}

		n := pollCount.Add(1)
		if n < 3 {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "approved",
			"decided_by": "admin@test.com",
			"reason":     "looks good",
		})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewApprovalBackend(client, WithPollInterval(50*time.Millisecond))

	ctx := context.Background()
	req, err := backend.RequestApproval(ctx, "Bash", map[string]any{"command": "ls"}, "Review this command")
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	decision, err := backend.PollApprovalStatus(ctx, req.ApprovalID())
	if err != nil {
		t.Fatalf("PollApprovalStatus: %v", err)
	}
	if !decision.Approved {
		t.Error("expected approved=true")
	}
	if decision.Status != approval.StatusApproved {
		t.Errorf("status: got %q, want %q", decision.Status, approval.StatusApproved)
	}
	if decision.Approver != "admin@test.com" {
		t.Errorf("approver: got %q, want %q", decision.Approver, "admin@test.com")
	}
	if decision.Reason != "looks good" {
		t.Errorf("reason: got %q, want %q", decision.Reason, "looks good")
	}
}

func TestApprovalRequestIncludesSessionID(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "approval-session"})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewApprovalBackend(client)
	req, err := backend.RequestApproval(context.Background(), "Bash", nil, "review", approval.WithSessionID("session-123"))
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if captured["session_id"] != "session-123" {
		t.Fatalf("session_id = %#v, want %q", captured["session_id"], "session-123")
	}
	if req.SessionID() != "session-123" {
		t.Fatalf("Request.SessionID() = %q, want %q", req.SessionID(), "session-123")
	}
}

func TestApprovalDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "approval-456"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "rejected",
			"decided_by": "security@test.com",
			"reason":     "too risky",
		})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewApprovalBackend(client, WithPollInterval(50*time.Millisecond))
	ctx := context.Background()

	req, err := backend.RequestApproval(ctx, "Bash", nil, "review")
	if err != nil {
		t.Fatal(err)
	}

	decision, err := backend.PollApprovalStatus(ctx, req.ApprovalID())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Approved {
		t.Error("expected approved=false for rejected")
	}
	if decision.Status != approval.StatusDenied {
		t.Errorf("status: got %q, want %q", decision.Status, approval.StatusDenied)
	}
}

func TestApprovalTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "approval-789"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "timed_out"})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewApprovalBackend(client, WithPollInterval(50*time.Millisecond))
	ctx := context.Background()

	req, err := backend.RequestApproval(ctx, "Bash", nil, "review")
	if err != nil {
		t.Fatal(err)
	}

	decision, err := backend.PollApprovalStatus(ctx, req.ApprovalID())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Approved {
		t.Error("expected approved=false for timeout")
	}
	if decision.Status != approval.StatusTimeout {
		t.Errorf("status: got %q, want %q", decision.Status, approval.StatusTimeout)
	}
}

func TestApprovalContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "approval-cancel"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewApprovalBackend(client, WithPollInterval(50*time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	decision, err := backend.PollApprovalStatus(ctx, "approval-cancel")
	if err == nil {
		t.Fatal("expected context error")
	}
	if decision.Status != approval.StatusTimeout {
		t.Errorf("status on cancel: got %q, want %q", decision.Status, approval.StatusTimeout)
	}
}
