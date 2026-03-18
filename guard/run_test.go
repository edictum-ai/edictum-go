package guard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
)

func nopCallable(_ map[string]any) (any, error) {
	return "ok", nil
}

func failCallable(_ map[string]any) (any, error) {
	return nil, errors.New("tool failed")
}

// 7.11: guard.Run() lifecycle
func TestRunLifecycle(t *testing.T) {
	preCalled := false
	postCalled := false
	hookCalled := false

	g := New(
		WithContracts(
			contract.Precondition{Name: "lifecycle-pre", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					preCalled = true
					return contract.Pass(), nil
				}},
			contract.Postcondition{Name: "lifecycle-post", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope, _ any) (contract.Verdict, error) {
					postCalled = true
					return contract.Pass(), nil
				}},
		),
		WithHooks(pipeline.HookRegistration{
			Phase: "before", Tool: "*", Name: "lifecycle-hook",
			Before: func(_ context.Context, _ envelope.ToolEnvelope) (pipeline.HookDecision, error) {
				hookCalled = true
				return pipeline.AllowHook(), nil
			},
		}),
	)

	ctx := context.Background()
	result, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result != "ok" {
		t.Errorf("result: got %v, want 'ok'", result)
	}
	if !preCalled {
		t.Error("precondition not called")
	}
	if !postCalled {
		t.Error("postcondition not called")
	}
	if !hookCalled {
		t.Error("hook not called")
	}

	// Audit should have at least CALL_ALLOWED and CALL_EXECUTED
	events := g.LocalSink().Events()
	if len(events) < 2 {
		t.Fatalf("audit events: got %d, want >= 2", len(events))
	}
	if events[0].Action != audit.ActionCallAllowed {
		t.Errorf("first event: got %v, want CALL_ALLOWED", events[0].Action)
	}
	if events[1].Action != audit.ActionCallExecuted {
		t.Errorf("second event: got %v, want CALL_EXECUTED", events[1].Action)
	}
}

func TestRunDeny(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "deny-rm", Tool: "Bash",
				Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
					if strings.Contains(env.BashCommand(), "rm -rf") {
						return contract.Fail("Cannot run rm -rf"), nil
					}
					return contract.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "rm -rf /"}, nopCallable)
	if err == nil {
		t.Fatal("expected DeniedError")
	}
	var denied *edictum.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected DeniedError, got %T: %v", err, err)
	}
	if denied.DecisionName != "deny-rm" {
		t.Errorf("decision_name: got %q, want %q", denied.DecisionName, "deny-rm")
	}
}

func TestRunObserveModeFallthrough(t *testing.T) {
	g := New(
		WithMode("observe"),
		WithContracts(
			contract.Precondition{Name: "observe-deny", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("would deny"), nil
				}},
		),
	)

	ctx := context.Background()
	result, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("observe mode should not error: %v", err)
	}
	if result != "ok" {
		t.Errorf("result: got %v, want 'ok'", result)
	}

	// Should have CALL_WOULD_DENY
	events := g.LocalSink().Events()
	hasWouldDeny := false
	for _, e := range events {
		if e.Action == audit.ActionCallWouldDeny {
			hasWouldDeny = true
		}
	}
	if !hasWouldDeny {
		t.Error("expected CALL_WOULD_DENY in observe mode")
	}
}

func TestRunToolError(t *testing.T) {
	g := New()
	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, failCallable)
	if err == nil {
		t.Fatal("expected ToolError")
	}
	var toolErr *edictum.ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("expected ToolError, got %T: %v", err, err)
	}
}

func TestRunWithSessionID(t *testing.T) {
	g := New()
	ctx := context.Background()
	result, err := g.Run(ctx, "Read", nil, nopCallable, WithSessionID("custom-session"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result != "ok" {
		t.Errorf("result: got %v, want 'ok'", result)
	}
}

func TestRunWithPrincipalOverride(t *testing.T) {
	var captured *envelope.Principal
	g := New(
		WithContracts(
			contract.Precondition{Name: "capture", Tool: "*",
				Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
					captured = env.Principal()
					return contract.Pass(), nil
				}},
		),
	)

	p := envelope.NewPrincipal(envelope.WithUserID("run-override"))
	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable,
		WithRunPrincipal(&p))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if captured == nil || captured.UserID() != "run-override" {
		t.Error("run-level principal should override guard-level")
	}
}

func TestRunPostconditionRedact(t *testing.T) {
	g := New(
		WithTools(map[string]map[string]any{
			"ReadFile": {"side_effect": "read", "idempotent": true},
		}),
		WithContracts(
			contract.Postcondition{
				Name:   "redact-secret",
				Tool:   "ReadFile",
				Effect: "redact",
				Check: func(_ context.Context, _ envelope.ToolEnvelope, _ any) (contract.Verdict, error) {
					return contract.Fail("contains secret"), nil
				},
			},
		),
	)

	ctx := context.Background()
	result, err := g.Run(ctx, "ReadFile", nil, func(_ map[string]any) (any, error) {
		return "secret data here", nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	s, ok := result.(string)
	if !ok {
		t.Fatalf("result type: got %T, want string", result)
	}
	if s != "[REDACTED]" {
		t.Errorf("result: got %q, want '[REDACTED]'", s)
	}
}

// TestRun_ObserveMode_ApprovalFallsThrough proves that in observe mode,
// a precondition with Effect="approve" does NOT block on approval.
// Instead it emits CALL_WOULD_DENY and executes the tool.
func TestRun_ObserveMode_ApprovalFallsThrough(t *testing.T) {
	toolExecuted := false
	g := New(
		WithMode("observe"),
		WithContracts(
			contract.Precondition{
				Name:   "needs-approval",
				Tool:   "*",
				Effect: "approve",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("requires human approval"), nil
				},
			},
		),
		// Deliberately NO approval backend -- in enforce mode this would
		// error. In observe mode it must not reach the backend at all.
	)

	ctx := context.Background()
	result, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"},
		func(_ map[string]any) (any, error) {
			toolExecuted = true
			return "executed", nil
		})
	if err != nil {
		t.Fatalf("observe mode should not error: %v", err)
	}
	if !toolExecuted {
		t.Fatal("tool should have been executed in observe mode")
	}
	if result != "executed" {
		t.Errorf("result: got %v, want 'executed'", result)
	}

	// Verify CALL_WOULD_DENY was emitted
	events := g.LocalSink().Events()
	hasWouldDeny := false
	for _, e := range events {
		if e.Action == audit.ActionCallWouldDeny {
			hasWouldDeny = true
			break
		}
	}
	if !hasWouldDeny {
		t.Error("expected CALL_WOULD_DENY audit event for approval in observe mode")
	}
}

// TestRun_ApprovalTimeoutPropagated proves that per-contract
// ApprovalTimeout and ApprovalTimeoutEff are passed to the approval backend.
func TestRun_ApprovalTimeoutPropagated(t *testing.T) {
	var capturedReq approval.Request
	mock := &mockApprovalBackend{
		onRequest: func(_ context.Context, _ string, _ map[string]any, _ string, opts ...approval.RequestOption) (approval.Request, error) {
			req := approval.Request{}
			for _, opt := range opts {
				opt(&req)
			}
			capturedReq = req
			return req, nil
		},
		onPoll: func(_ context.Context, _ string) (approval.Decision, error) {
			return approval.Decision{Approved: true, Status: approval.StatusApproved}, nil
		},
	}

	g := New(
		WithContracts(
			contract.Precondition{
				Name:          "approval-timeout",
				Tool:          "*",
				Effect:        "approve",
				Timeout:       60,
				TimeoutEffect: "allow",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("needs approval"), nil
				},
			},
		),
		WithApprovalBackend(mock),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if capturedReq.Timeout() != 60*1e9 { // 60 seconds in nanoseconds
		t.Errorf("timeout: got %v, want 60s", capturedReq.Timeout())
	}
	if capturedReq.TimeoutEffect() != "allow" {
		t.Errorf("timeout_effect: got %q, want 'allow'", capturedReq.TimeoutEffect())
	}
}

// mockApprovalBackend is a test double that records RequestApproval calls.
type mockApprovalBackend struct {
	onRequest func(ctx context.Context, toolName string, toolArgs map[string]any, message string, opts ...approval.RequestOption) (approval.Request, error)
	onPoll    func(ctx context.Context, approvalID string) (approval.Decision, error)
}

func (m *mockApprovalBackend) RequestApproval(ctx context.Context, toolName string, toolArgs map[string]any, message string, opts ...approval.RequestOption) (approval.Request, error) {
	return m.onRequest(ctx, toolName, toolArgs, message, opts...)
}

func (m *mockApprovalBackend) PollApprovalStatus(ctx context.Context, approvalID string) (approval.Decision, error) {
	return m.onPoll(ctx, approvalID)
}

func TestRunAttemptsIncrement(t *testing.T) {
	g := New()
	ctx := context.Background()

	// Run twice, each increments attempts
	for i := 0; i < 3; i++ {
		_, err := g.Run(ctx, "Read", nil, nopCallable)
		if err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
	}

	events := g.LocalSink().Events()
	// 3 allowed + 3 executed = 6 events
	if len(events) < 6 {
		t.Errorf("expected >= 6 events, got %d", len(events))
	}
}

func TestRun_ApprovalContextTimeout(t *testing.T) {
	// When context expires during approval polling, the guard should
	// treat it as a timeout and apply timeout_effect, not return raw error.
	g := New(
		WithContracts(
			contract.Precondition{
				Name: "needs-approval", Tool: "*", Effect: "approve",
				Timeout: 1, TimeoutEffect: "allow",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("needs approval"), nil
				},
			},
		),
		WithApprovalBackend(&blockingApprovalBackend{}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should succeed because timeout_effect="allow"
	result, err := g.Run(ctx, "TestTool", map[string]any{},
		func(_ map[string]any) (any, error) { return "executed", nil })
	if err != nil {
		t.Fatalf("expected allow on timeout, got error: %v", err)
	}
	if result != "executed" {
		t.Fatalf("expected 'executed', got %v", result)
	}
}

// blockingApprovalBackend always blocks on PollApprovalStatus until context cancels.
type blockingApprovalBackend struct{}

func (b *blockingApprovalBackend) RequestApproval(
	_ context.Context, toolName string, toolArgs map[string]any, message string, opts ...approval.RequestOption,
) (approval.Request, error) {
	return approval.NewRequest("test-id", toolName, toolArgs, message, opts...), nil
}

func (b *blockingApprovalBackend) PollApprovalStatus(
	ctx context.Context, _ string,
) (approval.Decision, error) {
	<-ctx.Done()
	return approval.Decision{}, ctx.Err()
}
