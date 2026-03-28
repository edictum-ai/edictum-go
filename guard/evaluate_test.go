package guard

import (
	"context"
	"errors"
	"testing"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// 7.12: Evaluate() dry-run
func TestEvaluateAllow(t *testing.T) {
	g := New(
		WithRules(
			rule.Precondition{Name: "pass-all", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Decision != "allow" {
		t.Errorf("decision: got %q, want 'allow'", result.Decision)
	}
	if result.RulesEvaluated != 1 {
		t.Errorf("contracts_evaluated: got %d, want 1", result.RulesEvaluated)
	}
	if len(result.BlockReasons) != 0 {
		t.Errorf("block_reasons: got %v, want empty", result.BlockReasons)
	}
}

func TestEvaluateDeny(t *testing.T) {
	g := New(
		WithRules(
			rule.Precondition{Name: "deny-rm", Tool: "Bash",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					if env.BashCommand() == "rm -rf /" {
						return rule.Fail("no rm -rf /"), nil
					}
					return rule.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "rm -rf /"})
	if result.Decision != "block" {
		t.Errorf("decision: got %q, want 'deny'", result.Decision)
	}
	if len(result.BlockReasons) != 1 {
		t.Errorf("block_reasons: got %d, want 1", len(result.BlockReasons))
	}
}

func TestEvaluateExhaustive(t *testing.T) {
	// Evaluate should check ALL rules, not short-circuit on first deny
	g := New(
		WithRules(
			rule.Precondition{Name: "deny-1", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("reason 1"), nil
				}},
			rule.Precondition{Name: "deny-2", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("reason 2"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Decision != "block" {
		t.Errorf("decision: got %q, want 'deny'", result.Decision)
	}
	if result.RulesEvaluated != 2 {
		t.Errorf("contracts_evaluated: got %d, want 2", result.RulesEvaluated)
	}
	if len(result.BlockReasons) != 2 {
		t.Errorf("block_reasons: got %d, want 2", len(result.BlockReasons))
	}
}

func TestEvaluateWithPostconditions(t *testing.T) {
	g := New(
		WithRules(
			rule.Postcondition{Name: "warn-post", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall, resp any) (rule.Decision, error) {
					if resp == "bad output" {
						return rule.Fail("output is bad"), nil
					}
					return rule.Pass(), nil
				}},
		),
	)

	ctx := context.Background()

	// Without output: postconditions skipped
	result1 := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result1.Decision != "allow" {
		t.Errorf("without output: decision=%q, want 'allow'", result1.Decision)
	}
	if result1.RulesEvaluated != 0 {
		t.Errorf("without output: rules=%d, want 0", result1.RulesEvaluated)
	}

	// With output: postconditions evaluated
	result2 := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"},
		WithOutput("bad output"))
	if result2.Decision != "warn" {
		t.Errorf("with output: decision=%q, want 'warn'", result2.Decision)
	}
	if len(result2.WarnReasons) != 1 {
		t.Errorf("warn_reasons: got %d, want 1", len(result2.WarnReasons))
	}
}

func TestEvaluateNoSessionRules(t *testing.T) {
	// Session rules should be skipped in dry-run
	sessionCalled := false
	g := New(
		WithRules(
			rule.SessionRule{Name: "sess", Check: func(_ context.Context, _ any) (rule.Decision, error) {
				sessionCalled = true
				return rule.Fail("session deny"), nil
			}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if sessionCalled {
		t.Error("session rules should not be called in Evaluate()")
	}
	if result.Decision != "allow" {
		t.Errorf("decision: got %q, want 'allow'", result.Decision)
	}
}

func TestEvaluateObserveContractNotDeny(t *testing.T) {
	g := New(
		WithRules(
			rule.Precondition{Name: "obs-pre", Tool: "*", Mode: "observe",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("observed deny"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	// Observe-mode rules don't count as real denials
	if result.Decision != "allow" {
		t.Errorf("decision: got %q, want 'allow' (observe rule)", result.Decision)
	}
	if result.RulesEvaluated != 1 {
		t.Errorf("contracts_evaluated: got %d, want 1", result.RulesEvaluated)
	}
	if len(result.Rules) != 1 || !result.Rules[0].Observed {
		t.Error("rule should be marked as observed")
	}
}

func TestEvaluatePolicyError(t *testing.T) {
	g := New(
		WithRules(
			rule.Precondition{Name: "error-pre", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Decision{}, errors.New("check failed")
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if !result.PolicyError {
		t.Error("policy_error should be true when rule raises error")
	}
	if result.Decision != "block" {
		t.Errorf("decision: got %q, want 'deny'", result.Decision)
	}
}

func TestEvaluateToolNameFiltering(t *testing.T) {
	g := New(
		WithRules(
			rule.Precondition{Name: "bash-only", Tool: "Bash",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("bash denied"), nil
				}},
		),
	)

	ctx := context.Background()

	// Bash: should be denied
	r1 := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if r1.Decision != "block" {
		t.Errorf("Bash decision: got %q, want 'deny'", r1.Decision)
	}

	// Read: should be allowed (rule doesn't match)
	r2 := g.Evaluate(ctx, "Read", nil)
	if r2.Decision != "allow" {
		t.Errorf("Read decision: got %q, want 'allow'", r2.Decision)
	}
}

func TestEvaluateEnvironmentOverride(t *testing.T) {
	var capturedEnv string
	g := New(
		WithEnvironment("production"),
		WithRules(
			rule.Precondition{Name: "env-check", Tool: "*",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					capturedEnv = env.Environment()
					return rule.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"},
		WithEvalEnvironment("staging"))
	if capturedEnv != "staging" {
		t.Errorf("environment: got %q, want 'staging'", capturedEnv)
	}
}

func TestEvaluateSandboxRules(t *testing.T) {
	g := New(
		WithSandboxRules(
			rule.Precondition{Name: "sandbox-deny", Tool: "*",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("sandbox blocked"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Decision != "block" {
		t.Errorf("decision: got %q, want 'deny'", result.Decision)
	}
	if len(result.Rules) != 1 || result.Rules[0].RuleType != "sandbox" {
		t.Error("sandbox rule should be evaluated with type 'sandbox'")
	}
}

// TestEvaluate_GuardPrincipalFallback proves that Evaluate() falls back
// to the guard-level principal when no WithEvalPrincipal option is set.
func TestEvaluate_GuardPrincipalFallback(t *testing.T) {
	var captured *toolcall.Principal
	principal := toolcall.NewPrincipal(toolcall.WithUserID("guard-user"))

	g := New(
		WithPrincipal(&principal),
		WithRules(
			rule.Precondition{Name: "capture-principal", Tool: "*",
				Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
					captured = env.Principal()
					return rule.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Decision != "allow" {
		t.Fatalf("decision: got %q, want 'allow'", result.Decision)
	}
	if captured == nil {
		t.Fatal("principal should not be nil -- guard-level principal was not propagated")
	}
	if captured.UserID() != "guard-user" {
		t.Errorf("principal.UserID: got %q, want 'guard-user'", captured.UserID())
	}
}

func TestEvaluateWithWhenPredicate(t *testing.T) {
	g := New(
		WithRules(
			rule.Precondition{Name: "when-skip", Tool: "*",
				When: func(_ context.Context, _ toolcall.ToolCall) bool {
					return false // always skip
				},
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("should not run"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Decision != "allow" {
		t.Errorf("decision: got %q, want 'allow' (when=false)", result.Decision)
	}
	if result.RulesEvaluated != 0 {
		t.Errorf("contracts_evaluated: got %d, want 0", result.RulesEvaluated)
	}
}
