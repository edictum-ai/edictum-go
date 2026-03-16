package guard

import (
	"context"
	"errors"
	"strings"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
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
