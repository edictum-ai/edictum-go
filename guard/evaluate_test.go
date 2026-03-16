package guard

import (
	"context"
	"errors"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

// 7.12: Evaluate() dry-run
func TestEvaluateAllow(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "pass-all", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Verdict != "allow" {
		t.Errorf("verdict: got %q, want 'allow'", result.Verdict)
	}
	if result.ContractsEvaluated != 1 {
		t.Errorf("contracts_evaluated: got %d, want 1", result.ContractsEvaluated)
	}
	if len(result.DenyReasons) != 0 {
		t.Errorf("deny_reasons: got %v, want empty", result.DenyReasons)
	}
}

func TestEvaluateDeny(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "deny-rm", Tool: "Bash",
				Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
					if env.BashCommand() == "rm -rf /" {
						return contract.Fail("no rm -rf /"), nil
					}
					return contract.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "rm -rf /"})
	if result.Verdict != "deny" {
		t.Errorf("verdict: got %q, want 'deny'", result.Verdict)
	}
	if len(result.DenyReasons) != 1 {
		t.Errorf("deny_reasons: got %d, want 1", len(result.DenyReasons))
	}
}

func TestEvaluateExhaustive(t *testing.T) {
	// Evaluate should check ALL contracts, not short-circuit on first deny
	g := New(
		WithContracts(
			contract.Precondition{Name: "deny-1", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("reason 1"), nil
				}},
			contract.Precondition{Name: "deny-2", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("reason 2"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Verdict != "deny" {
		t.Errorf("verdict: got %q, want 'deny'", result.Verdict)
	}
	if result.ContractsEvaluated != 2 {
		t.Errorf("contracts_evaluated: got %d, want 2", result.ContractsEvaluated)
	}
	if len(result.DenyReasons) != 2 {
		t.Errorf("deny_reasons: got %d, want 2", len(result.DenyReasons))
	}
}

func TestEvaluateWithPostconditions(t *testing.T) {
	g := New(
		WithContracts(
			contract.Postcondition{Name: "warn-post", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope, resp any) (contract.Verdict, error) {
					if resp == "bad output" {
						return contract.Fail("output is bad"), nil
					}
					return contract.Pass(), nil
				}},
		),
	)

	ctx := context.Background()

	// Without output: postconditions skipped
	result1 := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result1.Verdict != "allow" {
		t.Errorf("without output: verdict=%q, want 'allow'", result1.Verdict)
	}
	if result1.ContractsEvaluated != 0 {
		t.Errorf("without output: contracts=%d, want 0", result1.ContractsEvaluated)
	}

	// With output: postconditions evaluated
	result2 := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"},
		WithOutput("bad output"))
	if result2.Verdict != "warn" {
		t.Errorf("with output: verdict=%q, want 'warn'", result2.Verdict)
	}
	if len(result2.WarnReasons) != 1 {
		t.Errorf("warn_reasons: got %d, want 1", len(result2.WarnReasons))
	}
}

func TestEvaluateNoSessionContracts(t *testing.T) {
	// Session contracts should be skipped in dry-run
	sessionCalled := false
	g := New(
		WithContracts(
			contract.SessionContract{Name: "sess", Check: func(_ context.Context, _ any) (contract.Verdict, error) {
				sessionCalled = true
				return contract.Fail("session deny"), nil
			}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if sessionCalled {
		t.Error("session contracts should not be called in Evaluate()")
	}
	if result.Verdict != "allow" {
		t.Errorf("verdict: got %q, want 'allow'", result.Verdict)
	}
}

func TestEvaluateObserveContractNotDeny(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "obs-pre", Tool: "*", Mode: "observe",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("observed deny"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	// Observe-mode contracts don't count as real denials
	if result.Verdict != "allow" {
		t.Errorf("verdict: got %q, want 'allow' (observe contract)", result.Verdict)
	}
	if result.ContractsEvaluated != 1 {
		t.Errorf("contracts_evaluated: got %d, want 1", result.ContractsEvaluated)
	}
	if len(result.Contracts) != 1 || !result.Contracts[0].Observed {
		t.Error("contract should be marked as observed")
	}
}

func TestEvaluatePolicyError(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "error-pre", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Verdict{}, errors.New("check failed")
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if !result.PolicyError {
		t.Error("policy_error should be true when contract raises error")
	}
	if result.Verdict != "deny" {
		t.Errorf("verdict: got %q, want 'deny'", result.Verdict)
	}
}

func TestEvaluateToolNameFiltering(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "bash-only", Tool: "Bash",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("bash denied"), nil
				}},
		),
	)

	ctx := context.Background()

	// Bash: should be denied
	r1 := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if r1.Verdict != "deny" {
		t.Errorf("Bash verdict: got %q, want 'deny'", r1.Verdict)
	}

	// Read: should be allowed (contract doesn't match)
	r2 := g.Evaluate(ctx, "Read", nil)
	if r2.Verdict != "allow" {
		t.Errorf("Read verdict: got %q, want 'allow'", r2.Verdict)
	}
}

func TestEvaluateEnvironmentOverride(t *testing.T) {
	var capturedEnv string
	g := New(
		WithEnvironment("production"),
		WithContracts(
			contract.Precondition{Name: "env-check", Tool: "*",
				Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
					capturedEnv = env.Environment()
					return contract.Pass(), nil
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

func TestEvaluateSandboxContracts(t *testing.T) {
	g := New(
		WithSandboxContracts(
			contract.Precondition{Name: "sandbox-deny", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("sandbox blocked"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Verdict != "deny" {
		t.Errorf("verdict: got %q, want 'deny'", result.Verdict)
	}
	if len(result.Contracts) != 1 || result.Contracts[0].ContractType != "sandbox" {
		t.Error("sandbox contract should be evaluated with type 'sandbox'")
	}
}

// TestEvaluate_GuardPrincipalFallback proves that Evaluate() falls back
// to the guard-level principal when no WithEvalPrincipal option is set.
func TestEvaluate_GuardPrincipalFallback(t *testing.T) {
	var captured *envelope.Principal
	principal := envelope.NewPrincipal(envelope.WithUserID("guard-user"))

	g := New(
		WithPrincipal(&principal),
		WithContracts(
			contract.Precondition{Name: "capture-principal", Tool: "*",
				Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
					captured = env.Principal()
					return contract.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Verdict != "allow" {
		t.Fatalf("verdict: got %q, want 'allow'", result.Verdict)
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
		WithContracts(
			contract.Precondition{Name: "when-skip", Tool: "*",
				When: func(_ context.Context, _ envelope.ToolEnvelope) bool {
					return false // always skip
				},
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("should not run"), nil
				}},
		),
	)

	ctx := context.Background()
	result := g.Evaluate(ctx, "Bash", map[string]any{"command": "ls"})
	if result.Verdict != "allow" {
		t.Errorf("verdict: got %q, want 'allow' (when=false)", result.Verdict)
	}
	if result.ContractsEvaluated != 0 {
		t.Errorf("contracts_evaluated: got %d, want 0", result.ContractsEvaluated)
	}
}
