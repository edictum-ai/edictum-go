package eino

import (
	"context"
	"errors"
	"strings"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/guard"
)

func echoTool(_ context.Context, args map[string]any) (any, error) {
	return args, nil
}

func denyRmContract() rule.Precondition {
	return rule.Precondition{
		Name: "deny-rm",
		Tool: "Bash",
		Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
			if strings.Contains(env.BashCommand(), "rm") {
				return rule.Fail("rm is denied"), nil
			}
			return rule.Pass(), nil
		},
	}
}

// 11.1: WrapTool allows tool execution when no rules deny.
func TestWrapTool_Allow(t *testing.T) {
	g := guard.New()
	adapter := New(g)
	wrapped := adapter.WrapTool("Bash", echoTool)

	args := map[string]any{"command": "ls"}
	result, err := wrapped(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result type: got %T, want map[string]any", result)
	}
	if m["command"] != "ls" {
		t.Errorf("result[command]: got %v, want 'ls'", m["command"])
	}
}

// 11.2: WrapTool denies and does not execute the tool.
func TestWrapTool_Deny(t *testing.T) {
	g := guard.New(guard.WithRules(denyRmContract()))
	adapter := New(g)

	toolCalled := false
	wrapped := adapter.WrapTool("Bash", func(_ context.Context, _ map[string]any) (any, error) {
		toolCalled = true
		return nil, nil
	})

	_, err := wrapped(context.Background(), map[string]any{"command": "rm -rf /"})
	if err == nil {
		t.Fatal("expected error on deny")
	}
	if toolCalled {
		t.Error("tool should not have been called on deny")
	}
}

// 11.3: Deny reason is preserved in the error.
func TestWrapTool_DenyReason(t *testing.T) {
	g := guard.New(guard.WithRules(denyRmContract()))
	adapter := New(g)
	wrapped := adapter.WrapTool("Bash", echoTool)

	_, err := wrapped(context.Background(), map[string]any{"command": "rm -rf /"})
	if err == nil {
		t.Fatal("expected error on deny")
	}
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError, got %T: %v", err, err)
	}
	if denied.Reason != "rm is denied" {
		t.Errorf("reason: got %q, want %q", denied.Reason, "rm is denied")
	}
	if denied.DecisionName != "deny-rm" {
		t.Errorf("decision_name: got %q, want %q", denied.DecisionName, "deny-rm")
	}
}

// 11.4: In observe mode, deny becomes allow and tool executes.
func TestWrapTool_ObserveMode(t *testing.T) {
	g := guard.New(
		guard.WithMode("observe"),
		guard.WithRules(denyRmContract()),
	)
	adapter := New(g)

	toolCalled := false
	wrapped := adapter.WrapTool("Bash", func(_ context.Context, _ map[string]any) (any, error) {
		toolCalled = true
		return "observed", nil
	})

	result, err := wrapped(context.Background(), map[string]any{"command": "rm -rf /"})
	if err != nil {
		t.Fatalf("observe mode should not error: %v", err)
	}
	if !toolCalled {
		t.Error("tool should have been called in observe mode")
	}
	if result != "observed" {
		t.Errorf("result: got %v, want 'observed'", result)
	}
}
