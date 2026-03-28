package adkgo

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/guard"
)

// 11.1: Allow with no rules -- tool executes normally.
func TestAdapterParity_11_1_AllowNoContracts(t *testing.T) {
	g := guard.New()
	adapter := New(g)
	wrapped := adapter.WrapTool("ReadFile",
		func(_ context.Context, _ map[string]any) (any, error) {
			return "file contents", nil
		})

	result, err := wrapped(context.Background(), map[string]any{"path": "/tmp/x"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != "file contents" {
		t.Errorf("result: got %v, want 'file contents'", result)
	}
}

// 11.2: Deny precondition -- tool never executes.
func TestAdapterParity_11_2_DenyPrecondition(t *testing.T) {
	toolCalled := false
	g := guard.New(
		guard.WithRules(
			rule.Precondition{
				Name: "deny-all",
				Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("denied by policy"), nil
				},
			},
		),
	)

	adapter := New(g)
	wrapped := adapter.WrapTool("Bash",
		func(_ context.Context, _ map[string]any) (any, error) {
			toolCalled = true
			return "should not happen", nil
		})

	_, err := wrapped(context.Background(), map[string]any{"command": "ls"})
	if err == nil {
		t.Fatal("expected BlockedError, got nil")
	}
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError, got %T: %v", err, err)
	}
	if toolCalled {
		t.Error("tool should not have been called after deny")
	}
}

// 11.3: Deny reason preserved end-to-end.
func TestAdapterParity_11_3_DenyReasonPreserved(t *testing.T) {
	g := guard.New(
		guard.WithRules(
			rule.Precondition{
				Name: "no-rm",
				Tool: "Bash",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					if strings.Contains(env.BashCommand(), "rm -rf") {
						return rule.Fail("rm -rf is forbidden"), nil
					}
					return rule.Pass(), nil
				},
			},
		),
	)

	adapter := New(g)
	wrapped := adapter.WrapTool("Bash",
		func(_ context.Context, _ map[string]any) (any, error) {
			return nil, nil
		})

	_, err := wrapped(context.Background(), map[string]any{"command": "rm -rf /"})
	if err == nil {
		t.Fatal("expected BlockedError")
	}
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError, got %T: %v", err, err)
	}
	if denied.Reason != "rm -rf is forbidden" {
		t.Errorf("reason: got %q, want %q", denied.Reason, "rm -rf is forbidden")
	}
	if denied.DecisionName != "no-rm" {
		t.Errorf("decision_name: got %q, want %q", denied.DecisionName, "no-rm")
	}
}

// 11.4: Observe mode -- deny becomes allow, tool executes.
func TestAdapterParity_11_4_ObserveMode(t *testing.T) {
	toolCalled := false
	g := guard.New(
		guard.WithMode("observe"),
		guard.WithRules(
			rule.Precondition{
				Name: "would-deny",
				Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("should observe, not deny"), nil
				},
			},
		),
	)

	adapter := New(g)
	wrapped := adapter.WrapTool("Bash",
		func(_ context.Context, _ map[string]any) (any, error) {
			toolCalled = true
			return "executed", nil
		})

	result, err := wrapped(context.Background(), map[string]any{"command": "ls"})
	if err != nil {
		t.Fatalf("observe mode should not error: %v", err)
	}
	if !toolCalled {
		t.Error("tool should have been called in observe mode")
	}
	if result != "executed" {
		t.Errorf("result: got %v, want 'executed'", result)
	}
}

// 11.5: on_deny callback fires exactly once.
func TestAdapterParity_11_5_OnDenyCallback(t *testing.T) {
	var denyCount atomic.Int32
	var capturedReason string

	g := guard.New(
		guard.WithRules(
			rule.Precondition{
				Name: "deny-cb",
				Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("denied for test"), nil
				},
			},
		),
		guard.WithOnDeny(func(_ toolcall.ToolCall, reason string, _ string) {
			denyCount.Add(1)
			capturedReason = reason
		}),
	)

	adapter := New(g)
	wrapped := adapter.WrapTool("Bash",
		func(_ context.Context, _ map[string]any) (any, error) {
			return nil, nil
		})

	_, _ = wrapped(context.Background(), map[string]any{"command": "ls"})

	if denyCount.Load() != 1 {
		t.Errorf("on_deny count: got %d, want 1", denyCount.Load())
	}
	if capturedReason != "denied for test" {
		t.Errorf("on_deny reason: got %q, want %q", capturedReason, "denied for test")
	}
}

// 11.6: on_allow callback fires exactly once.
func TestAdapterParity_11_6_OnAllowCallback(t *testing.T) {
	var allowCount atomic.Int32

	g := guard.New(
		guard.WithOnAllow(func(_ toolcall.ToolCall) {
			allowCount.Add(1)
		}),
	)

	adapter := New(g)
	wrapped := adapter.WrapTool("ReadFile",
		func(_ context.Context, _ map[string]any) (any, error) {
			return "ok", nil
		})

	_, err := wrapped(context.Background(), map[string]any{"path": "/tmp/x"})
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
	if allowCount.Load() != 1 {
		t.Errorf("on_allow count: got %d, want 1", allowCount.Load())
	}
}

// 11.7: Custom success_check determines tool success.
func TestAdapterParity_11_7_CustomSuccessCheck(t *testing.T) {
	g := guard.New(
		guard.WithSuccessCheck(func(_ string, result any) bool {
			m, ok := result.(map[string]any)
			if !ok {
				return false
			}
			status, _ := m["status"].(string)
			return status == "ok"
		}),
	)

	adapter := New(g)

	// Tool returns a "failed" status -- success_check should mark it failed.
	wrapped := adapter.WrapTool("API",
		func(_ context.Context, _ map[string]any) (any, error) {
			return map[string]any{"status": "error", "message": "bad request"}, nil
		})

	_, err := wrapped(context.Background(), map[string]any{})
	if err == nil {
		t.Fatal("expected ToolError when success_check returns false")
	}
	var toolErr *edictum.ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("expected ToolError, got %T: %v", err, err)
	}
}

// 11.8: SetPrincipal propagates to toolcall.
func TestAdapterParity_11_8_SetPrincipal(t *testing.T) {
	var capturedPrincipal *toolcall.Principal

	g := guard.New(
		guard.WithRules(
			rule.Precondition{
				Name: "capture-principal",
				Tool: "*",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					capturedPrincipal = env.Principal()
					return rule.Pass(), nil
				},
			},
		),
	)

	p := toolcall.NewPrincipal(
		toolcall.WithUserID("user-42"),
		toolcall.WithRole("admin"),
	)
	g.SetPrincipal(&p)

	adapter := New(g)
	wrapped := adapter.WrapTool("ReadFile",
		func(_ context.Context, _ map[string]any) (any, error) {
			return "ok", nil
		})

	_, err := wrapped(context.Background(), map[string]any{"path": "/etc/hosts"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedPrincipal == nil {
		t.Fatal("principal should have been set")
	}
	if capturedPrincipal.UserID() != "user-42" {
		t.Errorf("user_id: got %q, want %q", capturedPrincipal.UserID(), "user-42")
	}
	if capturedPrincipal.Role() != "admin" {
		t.Errorf("role: got %q, want %q", capturedPrincipal.Role(), "admin")
	}
}

// 11.9: PrincipalResolver resolves per-call principal.
func TestAdapterParity_11_9_PrincipalResolver(t *testing.T) {
	var capturedPrincipal *toolcall.Principal

	g := guard.New(
		guard.WithPrincipalResolver(func(_ string, args map[string]any) *toolcall.Principal {
			userID, _ := args["user"].(string)
			p := toolcall.NewPrincipal(
				toolcall.WithUserID(userID),
				toolcall.WithRole("resolver-role"),
			)
			return &p
		}),
		guard.WithRules(
			rule.Precondition{
				Name: "capture-resolved",
				Tool: "*",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					capturedPrincipal = env.Principal()
					return rule.Pass(), nil
				},
			},
		),
	)

	adapter := New(g)
	wrapped := adapter.WrapTool("ReadFile",
		func(_ context.Context, _ map[string]any) (any, error) {
			return "ok", nil
		})

	_, err := wrapped(context.Background(),
		map[string]any{"path": "/tmp/x", "user": "resolved-user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedPrincipal == nil {
		t.Fatal("principal should have been resolved")
	}
	if capturedPrincipal.UserID() != "resolved-user" {
		t.Errorf("user_id: got %q, want %q",
			capturedPrincipal.UserID(), "resolved-user")
	}
	if capturedPrincipal.Role() != "resolver-role" {
		t.Errorf("role: got %q, want %q",
			capturedPrincipal.Role(), "resolver-role")
	}
}

// 11.10: on_postcondition_warn fires on postcondition failure.
func TestAdapterParity_11_10_OnPostconditionWarn(t *testing.T) {
	var warnCount atomic.Int32
	var capturedWarnings []string

	g := guard.New(
		guard.WithRules(
			rule.Postcondition{
				Name:   "warn-pii",
				Tool:   "*",
				Effect: "warn",
				Check: func(_ context.Context, _ toolcall.ToolCall, result any) (rule.Decision, error) {
					s, ok := result.(string)
					if ok && strings.Contains(s, "SSN") {
						return rule.Fail("PII detected: SSN"), nil
					}
					return rule.Pass(), nil
				},
			},
		),
		guard.WithOnPostWarn(func(_ toolcall.ToolCall, warnings []string) {
			warnCount.Add(1)
			capturedWarnings = warnings
		}),
	)

	adapter := New(g)
	wrapped := adapter.WrapTool("ReadFile",
		func(_ context.Context, _ map[string]any) (any, error) {
			return "User SSN: 123-45-6789", nil
		})

	result, err := wrapped(context.Background(), map[string]any{"path": "/data"})
	if err != nil {
		t.Fatalf("warn effect should not error: %v", err)
	}
	// Warn effect does not block -- result passes through.
	if result != "User SSN: 123-45-6789" {
		t.Errorf("result: got %v, want original string", result)
	}
	if warnCount.Load() != 1 {
		t.Errorf("on_post_warn count: got %d, want 1", warnCount.Load())
	}
	if len(capturedWarnings) != 1 {
		t.Fatalf("warnings length: got %d, want 1", len(capturedWarnings))
	}
	if !strings.Contains(capturedWarnings[0], "PII detected: SSN") {
		t.Errorf("warning should contain 'PII detected: SSN', got %q",
			capturedWarnings[0])
	}
}
