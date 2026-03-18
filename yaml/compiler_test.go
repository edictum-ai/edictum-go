package yaml

import (
	"testing"

	"github.com/edictum-ai/edictum-go/pipeline"
)

// TestCompile_ObserveSessionLimitsNotMerged verifies that a session contract
// in observe mode does NOT have its limits merged into the compiled bundle's
// Limits. Only enforce-mode session contracts contribute to global limits.
func TestCompile_ObserveSessionLimitsNotMerged(t *testing.T) {
	bundle := map[string]any{
		"apiVersion": "edictum/v1",
		"kind":       "ContractBundle",
		"defaults":   map[string]any{"mode": "enforce"},
		"contracts": []any{
			map[string]any{
				"id":   "sess-observe",
				"type": "session",
				"mode": "observe",
				"limits": map[string]any{
					"max_tool_calls": 5,
					"max_attempts":   10,
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
		t.Errorf("observe session should not change MaxToolCalls: got %d, want %d",
			compiled.Limits.MaxToolCalls, defaults.MaxToolCalls)
	}
	if compiled.Limits.MaxAttempts != defaults.MaxAttempts {
		t.Errorf("observe session should not change MaxAttempts: got %d, want %d",
			compiled.Limits.MaxAttempts, defaults.MaxAttempts)
	}
}

// TestCompile_EnforceSessionLimitsMerged is the positive counterpart:
// an enforce-mode session contract DOES merge its limits.
func TestCompile_EnforceSessionLimitsMerged(t *testing.T) {
	bundle := map[string]any{
		"apiVersion": "edictum/v1",
		"kind":       "ContractBundle",
		"defaults":   map[string]any{"mode": "enforce"},
		"contracts": []any{
			map[string]any{
				"id":   "sess-enforce",
				"type": "session",
				"limits": map[string]any{
					"max_tool_calls": 5,
					"max_attempts":   10,
				},
			},
		},
	}

	compiled, err := Compile(bundle)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if compiled.Limits.MaxToolCalls != 5 {
		t.Errorf("enforce session should set MaxToolCalls=5, got %d", compiled.Limits.MaxToolCalls)
	}
	if compiled.Limits.MaxAttempts != 10 {
		t.Errorf("enforce session should set MaxAttempts=10, got %d", compiled.Limits.MaxAttempts)
	}
}
