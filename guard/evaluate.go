package guard

import (
	"context"
	"fmt"

	"github.com/edictum-ai/edictum-go/toolcall"
)

// RuleResult is the result of evaluating a single rule.
type RuleResult struct {
	RuleID      string
	RuleType    string // "precondition" | "postcondition" | "sandbox"
	Passed      bool
	Message     string
	Observed    bool
	Effect      string
	PolicyError bool
}

// EvaluationResult is the result of offline rule evaluation.
type EvaluationResult struct {
	Decision        string // "allow" | "block" | "warn"
	ToolName        string
	Rules           []RuleResult
	BlockReasons    []string
	WarnReasons     []string
	RulesEvaluated  int
	PolicyError     bool
	WorkflowSkipped bool
	WorkflowReason  string
}

// EvalOption configures a single Evaluate() call.
type EvalOption func(*evalConfig)

type evalConfig struct {
	principal   *toolcall.Principal
	output      *string
	environment string
}

// WithEvalPrincipal overrides the principal for this evaluation.
func WithEvalPrincipal(p *toolcall.Principal) EvalOption {
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

// Evaluate performs an offline evaluation of a tool call against all
// matching rules. Unlike Run(), this never executes the tool and
// evaluates all matching rules exhaustively (no short-circuit on
// first deny). Session rules and workflow gates are skipped because
// they depend on runtime session state and persisted evidence.
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

	env2, err := toolcall.CreateToolCall(ctx, toolcall.CreateToolCallOptions{
		ToolName:    toolName,
		Args:        args,
		Environment: cfg.environment,
		Principal:   principal,
		Registry:    g.toolRegistry,
	})
	if err != nil {
		return EvaluationResult{
			Decision: "block",
			ToolName: toolName,
			BlockReasons: []string{
				fmt.Sprintf("Envelope creation error: %s", err),
			},
			RulesEvaluated: 0,
			PolicyError:    true,
		}
	}

	var rules []RuleResult
	var denyReasons []string
	var warnReasons []string

	// Evaluate preconditions (exhaustive, no short-circuit)
	g.mu.RLock()
	pres := filterPreconditions(g.state.preconditions, env2)
	obsPres := filterPreconditions(g.state.observePreconditions, env2)
	g.mu.RUnlock()
	for _, c := range pres {
		evalPrecondition(ctx, c, env2, "precondition", &rules, &denyReasons)
	}
	for _, c := range obsPres {
		evalPrecondition(ctx, c, env2, "precondition", &rules, &denyReasons)
	}

	// Evaluate sandbox rules (exhaustive, no short-circuit)
	g.mu.RLock()
	sandboxes := filterSandbox(g.state.sandboxRules, env2)
	obsSandboxes := filterSandbox(g.state.observeSandboxRules, env2)
	g.mu.RUnlock()
	for _, c := range sandboxes {
		evalPrecondition(ctx, c, env2, "sandbox", &rules, &denyReasons)
	}
	for _, c := range obsSandboxes {
		evalPrecondition(ctx, c, env2, "sandbox", &rules, &denyReasons)
	}

	// Evaluate postconditions only when output is provided
	if cfg.output != nil {
		g.mu.RLock()
		posts := filterPostconditions(g.state.postconditions, env2)
		obsPosts := filterPostconditions(g.state.observePostconditions, env2)
		g.mu.RUnlock()
		for _, c := range posts {
			evalPostcondition(ctx, c, env2, *cfg.output, &rules, &warnReasons)
		}
		for _, c := range obsPosts {
			evalPostcondition(ctx, c, env2, *cfg.output, &rules, &warnReasons)
		}
	}

	// Compute decision
	decision := "allow"
	if len(denyReasons) > 0 {
		decision = "block"
	} else if len(warnReasons) > 0 {
		decision = "warn"
	}

	policyError := false
	for _, cr := range rules {
		if cr.PolicyError {
			policyError = true
			break
		}
	}

	rt := g.GetWorkflowRuntime()
	return EvaluationResult{
		Decision:        decision,
		ToolName:        toolName,
		Rules:           rules,
		BlockReasons:    denyReasons,
		WarnReasons:     warnReasons,
		RulesEvaluated:  len(rules),
		PolicyError:     policyError,
		WorkflowSkipped: rt != nil,
		WorkflowReason:  workflowSkipReason(rt != nil),
	}
}

func workflowSkipReason(skipped bool) string {
	if !skipped {
		return ""
	}
	return "workflow evaluation requires runtime session state and is enforced only by Run() in M1"
}
