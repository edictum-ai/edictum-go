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
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
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
		WithRules(
			rule.Precondition{Name: "lifecycle-pre", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					preCalled = true
					return rule.Pass(), nil
				}},
			rule.Postcondition{Name: "lifecycle-post", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
					postCalled = true
					return rule.Pass(), nil
				}},
		),
		WithHooks(pipeline.HookRegistration{
			Phase: "before", Tool: "*", Name: "lifecycle-hook",
			Before: func(_ context.Context, _ toolcall.ToolCall) (pipeline.HookDecision, error) {
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
		WithRules(
			rule.Precondition{Name: "deny-rm", Tool: "Bash",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					if strings.Contains(env.BashCommand(), "rm -rf") {
						return rule.Fail("Cannot run rm -rf"), nil
					}
					return rule.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "rm -rf /"}, nopCallable)
	if err == nil {
		t.Fatal("expected BlockedError")
	}
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError, got %T: %v", err, err)
	}
	if denied.DecisionName != "deny-rm" {
		t.Errorf("decision_name: got %q, want %q", denied.DecisionName, "deny-rm")
	}
}

func TestRunObserveModeFallthrough(t *testing.T) {
	g := New(
		WithMode("observe"),
		WithRules(
			rule.Precondition{Name: "observe-deny", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("would deny"), nil
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
	var captured *toolcall.Principal
	g := New(
		WithRules(
			rule.Precondition{Name: "capture", Tool: "*",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					captured = env.Principal()
					return rule.Pass(), nil
				}},
		),
	)

	p := toolcall.NewPrincipal(toolcall.WithUserID("run-override"))
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
		WithRules(
			rule.Postcondition{
				Name:   "redact-secret",
				Tool:   "ReadFile",
				Effect: "redact",
				Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
					return rule.Fail("contains secret"), nil
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

// TestRun_ObserveMode_ApprovalUsesBackend proves that observe mode still
// honors pending_approval instead of bypassing it.
func TestRun_ObserveMode_ApprovalUsesBackend(t *testing.T) {
	requested := 0
	polled := 0
	toolExecuted := false
	mock := &mockApprovalBackend{
		onRequest: func(_ context.Context, _ string, _ map[string]any, _ string, _ ...approval.RequestOption) (approval.Request, error) {
			requested++
			return approval.NewRequest("observe-approval", "Bash", nil, "needs approval"), nil
		},
		onPoll: func(_ context.Context, _ string) (approval.Decision, error) {
			polled++
			return approval.Decision{Approved: true, Status: approval.StatusApproved}, nil
		},
	}

	g := New(
		WithMode("observe"),
		WithRules(
			rule.Precondition{
				Name:   "needs-approval",
				Tool:   "*",
				Effect: "ask",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("requires human approval"), nil
				},
			},
		),
		WithApprovalBackend(mock),
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
	if requested != 1 || polled != 1 {
		t.Fatalf("approval backend calls = request:%d poll:%d, want 1 each", requested, polled)
	}
	events := g.LocalSink().Events()
	actions := make([]audit.Action, 0, len(events))
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	if len(actions) < 2 || actions[0] != audit.ActionCallApprovalRequested || actions[1] != audit.ActionCallApprovalGranted {
		t.Fatalf("unexpected leading audit actions: %v", actions)
	}
}

// TestRun_ApprovalTimeoutPropagated proves that per-rule
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
		WithRules(
			rule.Precondition{
				Name:          "approval-timeout",
				Tool:          "*",
				Effect:        "ask",
				Timeout:       60,
				TimeoutEffect: "allow",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("needs approval"), nil
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
		t.Errorf("timeout_action: got %q, want 'allow'", capturedReq.TimeoutEffect())
	}
}

func TestRun_DenialAuditIncludesPythonStyleFields(t *testing.T) {
	g := New(
		WithRules(rule.Precondition{
			Name: "deny-all",
			Tool: "*",
			Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
				return rule.Fail("blocked"), nil
			},
		}),
	)

	principal := toolcall.NewPrincipal(
		toolcall.WithUserID("u-123"),
		toolcall.WithClaims(map[string]any{"team": "security"}),
	)

	_, err := g.Run(context.Background(), "Bash", map[string]any{"command": "ls"}, nopCallable,
		WithRunPrincipal(&principal))
	if err == nil {
		t.Fatal("expected denial")
	}

	events := g.LocalSink().Events()
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	event := events[0]
	if event.Action != audit.ActionCallDenied {
		t.Fatalf("Action = %q, want %q", event.Action, audit.ActionCallDenied)
	}
	if event.Mode != "enforce" {
		t.Fatalf("Mode = %q, want enforce", event.Mode)
	}
	if len(event.ContractsEvaluated) != 1 {
		t.Fatalf("ContractsEvaluated len = %d, want 1", len(event.ContractsEvaluated))
	}
	if len(event.HooksEvaluated) != 0 {
		t.Fatalf("HooksEvaluated len = %d, want 0", len(event.HooksEvaluated))
	}
	if event.Principal == nil {
		t.Fatal("expected principal in audit event")
	}
	principalMap, ok := event.Principal.(map[string]any)
	if !ok {
		t.Fatalf("principal type = %T, want map[string]any", event.Principal)
	}
	if principalMap["user_id"] != "u-123" {
		t.Fatalf("principal.user_id = %v", principalMap["user_id"])
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
	// treat it as a timeout and apply timeout_action, not return raw error.
	g := New(
		WithRules(
			rule.Precondition{
				Name: "needs-approval", Tool: "*", Effect: "ask",
				Timeout: 1, TimeoutEffect: "allow",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("needs approval"), nil
				},
			},
		),
		WithApprovalBackend(&blockingApprovalBackend{}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should succeed because timeout_action="allow"
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
