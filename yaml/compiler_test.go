package yaml

import (
	"testing"
)

// TestCompile_ExplicitObserveSessionLimitsMerged verifies that a
// user-authored mode: observe session contract still contributes its limits.
func TestCompile_ExplicitObserveSessionLimitsMerged(t *testing.T) {
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
	if compiled.Limits.MaxToolCalls != 5 {
		t.Errorf("observe session should set MaxToolCalls=5, got %d", compiled.Limits.MaxToolCalls)
	}
	if compiled.Limits.MaxAttempts != 10 {
		t.Errorf("observe session should set MaxAttempts=10, got %d", compiled.Limits.MaxAttempts)
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

// TestCompile_InternalObserveShadowSessionLimitsNotMerged verifies that only
// internal _observe shadow copies skip global limit merging.
func TestCompile_InternalObserveShadowSessionLimitsNotMerged(t *testing.T) {
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
				},
			},
			map[string]any{
				"id":       "sess-shadow",
				"type":     "session",
				"mode":     "observe",
				"_observe": true,
				"limits": map[string]any{
					"max_tool_calls": 2,
				},
			},
		},
	}

	compiled, err := Compile(bundle)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if compiled.Limits.MaxToolCalls != 5 {
		t.Fatalf("internal observe shadow should not merge: got %d want 5", compiled.Limits.MaxToolCalls)
	}
}
