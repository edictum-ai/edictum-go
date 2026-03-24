package yaml

import (
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
)

func TestRegression_SchemaRejectsMalformedPostEffectLikePython(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-bundle
defaults:
  mode: enforce
contracts:
  - id: bad-post
    type: post
    tool: Bash
    when:
      "output.text":
        contains: "secret"
    then:
      effect: approve
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

func TestRegression_ExplicitObserveSessionLimitDoesNotMergeButExplicitEnforceDoes(t *testing.T) {
	bundle := map[string]any{
		"apiVersion": "edictum/v1",
		"kind":       "ContractBundle",
		"metadata":   map[string]any{"name": "test-bundle"},
		"defaults":   map[string]any{"mode": "observe"},
		"contracts": []any{
			map[string]any{
				"id":   "observe-limit",
				"type": "session",
				"mode": "observe",
				"limits": map[string]any{
					"max_tool_calls": 5,
				},
				"then": map[string]any{
					"effect":  "deny",
					"message": "observe",
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
					"effect":  "deny",
					"message": "enforce",
				},
			},
		},
	}

	compiled, err := Compile(bundle)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	defaults := pipeline.DefaultLimits()
	if compiled.Limits.MaxToolCalls != defaults.MaxToolCalls {
		t.Fatalf("observe-mode session limit should not merge: got %d want %d", compiled.Limits.MaxToolCalls, defaults.MaxToolCalls)
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

func envelopeOpts(tool string, args map[string]any) envelope.CreateEnvelopeOptions {
	return envelope.CreateEnvelopeOptions{ToolName: tool, Args: args}
}
