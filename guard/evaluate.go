package guard

import (
	"context"
	"fmt"

	"github.com/edictum-ai/edictum-go/envelope"
)

// ContractResult is the result of evaluating a single contract.
type ContractResult struct {
	ContractID   string
	ContractType string // "precondition" | "postcondition" | "sandbox"
	Passed       bool
	Message      string
	Observed     bool
	Effect       string
	PolicyError  bool
}

// EvaluationResult is the result of dry-run evaluation.
type EvaluationResult struct {
	Verdict            string // "allow" | "deny" | "warn"
	ToolName           string
	Contracts          []ContractResult
	DenyReasons        []string
	WarnReasons        []string
	ContractsEvaluated int
	PolicyError        bool
}

// EvalOption configures a single Evaluate() invocation.
type EvalOption func(*evalConfig)

type evalConfig struct {
	principal   *envelope.Principal
	output      *string
	environment string
}

// WithEvalPrincipal overrides the principal for this evaluation.
func WithEvalPrincipal(p *envelope.Principal) EvalOption {
	return func(c *evalConfig) { c.principal = p }
}

// WithOutput provides a simulated tool output for postcondition evaluation.
func WithOutput(output string) EvalOption {
	return func(c *evalConfig) { c.output = &output }
}

// WithEvalEnvironment overrides the environment for this evaluation.
func WithEvalEnvironment(env string) EvalOption {
	return func(c *evalConfig) { c.environment = env }
}

// Evaluate performs a dry-run evaluation of a tool call against all
// matching contracts. Unlike Run(), this never executes the tool and
// evaluates all matching contracts exhaustively (no short-circuit on
// first deny). Session contracts are skipped (no session state).
func (g *Guard) Evaluate(
	ctx context.Context,
	toolName string,
	args map[string]any,
	opts ...EvalOption,
) EvaluationResult {
	g.mu.RLock()
	envName := g.environment
	g.mu.RUnlock()

	cfg := &evalConfig{environment: envName}
	for _, opt := range opts {
		opt(cfg)
	}

	// Fall back to guard-level principal, matching Run() behavior.
	principal := cfg.principal
	if principal == nil {
		g.mu.RLock()
		principal = g.resolvePrincipal(toolName, args)
		g.mu.RUnlock()
	}

	env2, err := envelope.CreateEnvelope(ctx, envelope.CreateEnvelopeOptions{
		ToolName:    toolName,
		Args:        args,
		Environment: cfg.environment,
		Principal:   principal,
		Registry:    g.toolRegistry,
	})
	if err != nil {
		return EvaluationResult{
			Verdict:  "deny",
			ToolName: toolName,
			DenyReasons: []string{
				fmt.Sprintf("Envelope creation error: %s", err),
			},
			ContractsEvaluated: 0,
			PolicyError:        true,
		}
	}

	var contracts []ContractResult
	var denyReasons []string
	var warnReasons []string

	// Evaluate preconditions (exhaustive, no short-circuit)
	g.mu.RLock()
	pres := filterPreconditions(g.state.preconditions, env2)
	obsPres := filterPreconditions(g.state.observePreconditions, env2)
	g.mu.RUnlock()
	for _, c := range pres {
		evalPrecondition(ctx, c, env2, "precondition", &contracts, &denyReasons)
	}
	for _, c := range obsPres {
		evalPrecondition(ctx, c, env2, "precondition", &contracts, &denyReasons)
	}

	// Evaluate sandbox contracts (exhaustive, no short-circuit)
	g.mu.RLock()
	sandboxes := filterSandbox(g.state.sandboxContracts, env2)
	obsSandboxes := filterSandbox(g.state.observeSandboxContracts, env2)
	g.mu.RUnlock()
	for _, c := range sandboxes {
		evalPrecondition(ctx, c, env2, "sandbox", &contracts, &denyReasons)
	}
	for _, c := range obsSandboxes {
		evalPrecondition(ctx, c, env2, "sandbox", &contracts, &denyReasons)
	}

	// Evaluate postconditions only when output is provided
	if cfg.output != nil {
		g.mu.RLock()
		posts := filterPostconditions(g.state.postconditions, env2)
		obsPosts := filterPostconditions(g.state.observePostconditions, env2)
		g.mu.RUnlock()
		for _, c := range posts {
			evalPostcondition(ctx, c, env2, *cfg.output, &contracts, &warnReasons)
		}
		for _, c := range obsPosts {
			evalPostcondition(ctx, c, env2, *cfg.output, &contracts, &warnReasons)
		}
	}

	// Compute verdict
	verdict := "allow"
	if len(denyReasons) > 0 {
		verdict = "deny"
	} else if len(warnReasons) > 0 {
		verdict = "warn"
	}

	policyError := false
	for _, cr := range contracts {
		if cr.PolicyError {
			policyError = true
			break
		}
	}

	return EvaluationResult{
		Verdict:            verdict,
		ToolName:           toolName,
		Contracts:          contracts,
		DenyReasons:        denyReasons,
		WarnReasons:        warnReasons,
		ContractsEvaluated: len(contracts),
		PolicyError:        policyError,
	}
}
