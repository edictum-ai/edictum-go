package guard

import (
	"context"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

// 9.1: on_deny fires exactly once
func TestOnDenyFiresOnce(t *testing.T) {
	denyCount := 0
	g := New(
		WithContracts(
			contract.Precondition{Name: "deny-all", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("denied"), nil
				}},
		),
		WithOnDeny(func(_ envelope.ToolEnvelope, reason string, name string) {
			denyCount++
			if reason != "denied" {
				t.Errorf("deny reason: got %q, want %q", reason, "denied")
			}
			if name != "deny-all" {
				t.Errorf("deny name: got %q, want %q", name, "deny-all")
			}
		}),
	)

	ctx := context.Background()
	_, _ = g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if denyCount != 1 {
		t.Errorf("on_deny count: got %d, want 1", denyCount)
	}
}

// 9.2: on_allow fires exactly once
func TestOnAllowFiresOnce(t *testing.T) {
	allowCount := 0
	g := New(
		WithOnAllow(func(_ envelope.ToolEnvelope) {
			allowCount++
		}),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if allowCount != 1 {
		t.Errorf("on_allow count: got %d, want 1", allowCount)
	}
}

// 9.3: on_postcondition_warn fires with warnings
func TestOnPostWarn(t *testing.T) {
	var capturedWarnings []string
	g := New(
		WithContracts(
			contract.Postcondition{Name: "warn-post", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope, _ any) (contract.Verdict, error) {
					return contract.Fail("data issue"), nil
				}},
		),
		WithOnPostWarn(func(_ envelope.ToolEnvelope, warnings []string) {
			capturedWarnings = warnings
		}),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(capturedWarnings) == 0 {
		t.Fatal("on_post_warn should have been called with warnings")
	}
	found := false
	for _, w := range capturedWarnings {
		if strings.Contains(w, "data issue") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings should contain 'data issue': %v", capturedWarnings)
	}
}

// 9.4: on_deny skipped in observe mode
func TestOnDenySkippedInObserve(t *testing.T) {
	denyCount := 0
	g := New(
		WithMode("observe"),
		WithContracts(
			contract.Precondition{Name: "deny-obs", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("would deny"), nil
				}},
		),
		WithOnDeny(func(_ envelope.ToolEnvelope, _ string, _ string) {
			denyCount++
		}),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if denyCount != 0 {
		t.Errorf("on_deny should not fire in observe mode: count=%d", denyCount)
	}
}

// 9.5: callback errors don't crash
func TestCallbackErrorsDontCrash(t *testing.T) {
	g := New(
		WithOnAllow(func(_ envelope.ToolEnvelope) {
			panic("on_allow panicked")
		}),
	)

	ctx := context.Background()
	result, err := g.Run(ctx, "Read", nil, nopCallable)
	if err != nil {
		t.Fatalf("callback panic should be swallowed: %v", err)
	}
	if result != "ok" {
		t.Errorf("result: got %v, want 'ok'", result)
	}
}

func TestCallbackDenyPanicDontCrash(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "deny", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("denied"), nil
				}},
		),
		WithOnDeny(func(_ envelope.ToolEnvelope, _ string, _ string) {
			panic("on_deny panicked")
		}),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	// Should still get DeniedError, not a panic
	if err == nil {
		t.Fatal("expected DeniedError")
	}
}

func TestCallbackPostWarnPanicDontCrash(t *testing.T) {
	g := New(
		WithContracts(
			contract.Postcondition{Name: "warn", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope, _ any) (contract.Verdict, error) {
					return contract.Fail("warning"), nil
				}},
		),
		WithOnPostWarn(func(_ envelope.ToolEnvelope, _ []string) {
			panic("on_post_warn panicked")
		}),
	)

	ctx := context.Background()
	result, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("post warn panic should be swallowed: %v", err)
	}
	if result != "ok" {
		t.Errorf("result: got %v, want 'ok'", result)
	}
}

// 9.6: Custom success_check
func TestCustomSuccessCheck(t *testing.T) {
	g := New(
		WithSuccessCheck(func(_ string, _ any) bool {
			// Always reports failure
			return false
		}),
	)

	ctx := context.Background()
	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err == nil {
		t.Fatal("expected ToolError with custom success check returning false")
	}
}

// 9.7: Default success heuristic
func TestDefaultSuccessHeuristic(t *testing.T) {
	// nil result -> success
	g := New()
	ctx := context.Background()
	result, err := g.Run(ctx, "Read", nil, func(_ map[string]any) (any, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("nil result should be success: %v", err)
	}
	if result != nil {
		t.Errorf("result: got %v, want nil", result)
	}
}

func TestDefaultSuccessHeuristicErrorString(t *testing.T) {
	g := New()
	ctx := context.Background()
	_, err := g.Run(ctx, "Read", nil, func(_ map[string]any) (any, error) {
		return "error: something broke", nil
	})
	if err == nil {
		t.Fatal("'error:' prefix should be detected as failure")
	}
}

func TestDefaultSuccessHeuristicMapIsError(t *testing.T) {
	g := New()
	ctx := context.Background()
	_, err := g.Run(ctx, "Read", nil, func(_ map[string]any) (any, error) {
		return map[string]any{"is_error": true, "message": "bad"}, nil
	})
	if err == nil {
		t.Fatal("map with is_error=true should be detected as failure")
	}
}
