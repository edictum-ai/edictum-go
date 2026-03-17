package langchaingo

import (
	"context"
	"errors"
	"strings"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/guard"
)

func echoTool(_ context.Context, input string) (string, error) {
	return "echo:" + input, nil
}

func denyRmContract() contract.Precondition {
	return contract.Precondition{
		Name: "deny-rm",
		Tool: "Bash",
		Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
			if strings.Contains(env.BashCommand(), "rm") {
				return contract.Fail("rm is denied"), nil
			}
			return contract.Pass(), nil
		},
	}
}

// 11.1: WrapTool allows tool execution when no contracts deny.
func TestWrapTool_Allow(t *testing.T) {
	g := guard.New()
	adapter := New(g)
	wrapped := adapter.WrapTool("Bash", echoTool)

	result, err := wrapped(context.Background(), `{"command":"ls"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != `echo:{"command":"ls"}` {
		t.Errorf("result: got %q, want %q", result, `echo:{"command":"ls"}`)
	}
}

// 11.2: WrapTool denies and does not execute the tool.
func TestWrapTool_Deny(t *testing.T) {
	g := guard.New(guard.WithContracts(denyRmContract()))
	adapter := New(g)

	toolCalled := false
	wrapped := adapter.WrapTool("Bash", func(_ context.Context, _ string) (string, error) {
		toolCalled = true
		return "should not happen", nil
	})

	_, err := wrapped(context.Background(), `{"command":"rm -rf /"}`)
	if err == nil {
		t.Fatal("expected error on deny")
	}
	if toolCalled {
		t.Error("tool should not have been called on deny")
	}
}

// 11.3: Deny reason is preserved in the error.
func TestWrapTool_DenyReason(t *testing.T) {
	g := guard.New(guard.WithContracts(denyRmContract()))
	adapter := New(g)
	wrapped := adapter.WrapTool("Bash", echoTool)

	_, err := wrapped(context.Background(), `{"command":"rm -rf /"}`)
	if err == nil {
		t.Fatal("expected error on deny")
	}
	var denied *edictum.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected DeniedError, got %T: %v", err, err)
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
		guard.WithContracts(denyRmContract()),
	)
	adapter := New(g)

	toolCalled := false
	wrapped := adapter.WrapTool("Bash", func(_ context.Context, input string) (string, error) {
		toolCalled = true
		return "observed:" + input, nil
	})

	result, err := wrapped(context.Background(), `{"command":"rm -rf /"}`)
	if err != nil {
		t.Fatalf("observe mode should not error: %v", err)
	}
	if !toolCalled {
		t.Error("tool should have been called in observe mode")
	}
	if result != `observed:{"command":"rm -rf /"}` {
		t.Errorf("result: got %q", result)
	}
}

// TestWrapTool_NonJSONInput verifies fallback to {"input": raw} for non-JSON.
func TestWrapTool_NonJSONInput(t *testing.T) {
	var capturedArgs map[string]any
	g := guard.New(guard.WithContracts(
		contract.Precondition{
			Name: "capture",
			Tool: "*",
			Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
				capturedArgs = env.Args()
				return contract.Pass(), nil
			},
		},
	))
	adapter := New(g)
	wrapped := adapter.WrapTool("Search", echoTool)

	_, err := wrapped(context.Background(), "plain text query")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedArgs["input"] != "plain text query" {
		t.Errorf("args[input]: got %v, want %q", capturedArgs["input"], "plain text query")
	}
}
