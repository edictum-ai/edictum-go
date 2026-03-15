package pipeline

import "testing"

func TestDefaultLimits(t *testing.T) {
	limits := DefaultLimits()

	if limits.MaxAttempts != 500 {
		t.Errorf("MaxAttempts = %d, want 500", limits.MaxAttempts)
	}
	if limits.MaxToolCalls != 200 {
		t.Errorf("MaxToolCalls = %d, want 200", limits.MaxToolCalls)
	}
	if limits.MaxCallsPerTool == nil {
		t.Fatal("MaxCallsPerTool is nil, want empty map")
	}
	if len(limits.MaxCallsPerTool) != 0 {
		t.Errorf("MaxCallsPerTool has %d entries, want 0", len(limits.MaxCallsPerTool))
	}
}

func TestOperationLimits(t *testing.T) {
	t.Run("custom values", func(t *testing.T) {
		limits := OperationLimits{
			MaxAttempts:  100,
			MaxToolCalls: 50,
			MaxCallsPerTool: map[string]int{
				"Bash":  10,
				"Write": 5,
			},
		}

		if limits.MaxAttempts != 100 {
			t.Errorf("MaxAttempts = %d, want 100", limits.MaxAttempts)
		}
		if limits.MaxToolCalls != 50 {
			t.Errorf("MaxToolCalls = %d, want 50", limits.MaxToolCalls)
		}
		if got := limits.MaxCallsPerTool["Bash"]; got != 10 {
			t.Errorf("MaxCallsPerTool[Bash] = %d, want 10", got)
		}
		if got := limits.MaxCallsPerTool["Write"]; got != 5 {
			t.Errorf("MaxCallsPerTool[Write] = %d, want 5", got)
		}
	})

	t.Run("per tool empty by default", func(t *testing.T) {
		limits := DefaultLimits()

		if _, exists := limits.MaxCallsPerTool["Bash"]; exists {
			t.Error("MaxCallsPerTool contains 'Bash', want absent")
		}
	})
}
