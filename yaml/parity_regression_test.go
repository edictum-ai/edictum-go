package yaml

import (
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/toolcall"
)

func TestRegression_SchemaRejectsMalformedPostEffectLikePython(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: bad-post
    type: post
    tool: Bash
    when:
      "output.text":
        contains: "secret"
    then:
      action: ask
      message: "bad"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected schema validation error")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "schema validation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegression_ExplicitObserveSessionLimitMergesButInternalObserveShadowDoesNot(t *testing.T) {
	bundle := map[string]any{
		"apiVersion": "edictum/v1",
		"kind":       "Ruleset",
		"metadata":   map[string]any{"name": "test-bundle"},
		"defaults":   map[string]any{"mode": "observe"},
		"rules": []any{
			map[string]any{
				"id":   "observe-limit",
				"type": "session",
				"mode": "observe",
				"limits": map[string]any{
					"max_tool_calls": 5,
				},
				"then": map[string]any{
					"action":  "block",
					"message": "observe",
				},
			},
			map[string]any{
				"id":       "observe-shadow",
				"type":     "session",
				"mode":     "observe",
				"_observe": true,
				"limits": map[string]any{
					"max_tool_calls": 3,
				},
				"then": map[string]any{
					"action":  "block",
					"message": "shadow",
				},
			},
			map[string]any{
				"id":   "enforce-limit",
				"type": "session",
				"mode": "enforce",
				"limits": map[string]any{
					"max_attempts": 7,
				},
				"then": map[string]any{
					"action":  "block",
					"message": "enforce",
				},
			},
		},
	}

	compiled, err := Compile(bundle)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if compiled.Limits.MaxToolCalls != 5 {
		t.Fatalf("explicit observe-mode session limit should merge: got %d want 5", compiled.Limits.MaxToolCalls)
	}
	if compiled.Limits.MaxAttempts != 7 {
		t.Fatalf("explicit enforce-mode session limit should merge: got %d want 7", compiled.Limits.MaxAttempts)
	}
}

func TestRegression_ExpandMessageMatchesPythonPlaceholderBehavior(t *testing.T) {
	env := makeEnv(t, envelopeOpts("TestTool", map[string]any{
		"token": "sk-abcdefghijklmnopqrstuvwxyz",
		"path":  "/tmp/test.txt",
	}))

	msg := expandMessage("Token: {args.token}; Path: {args.path}; Missing: {args.missing}", env, "", nil, false)
	if msg != "Token: [REDACTED]; Path: /tmp/test.txt; Missing: {args.missing}" {
		t.Fatalf("expandMessage() = %q", msg)
	}
}

func TestRegression_OutputTextEmptyStringIsPresent(t *testing.T) {
	env := makeEnv(t, envelopeOpts("TestTool", nil))

	if got := EvaluateExpression(leaf("output.text", "exists", true), env, ""); !got.Matched {
		t.Fatal("expected output.text exists=true to match for empty string")
	}
	if got := EvaluateExpression(leaf("output.text", "equals", ""), env, ""); !got.Matched {
		t.Fatal("expected output.text equals empty string to match")
	}
}

func envelopeOpts(tool string, args map[string]any) toolcall.CreateToolCallOptions {
	return toolcall.CreateToolCallOptions{ToolName: tool, Args: args}
}
