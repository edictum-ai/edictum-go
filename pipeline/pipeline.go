package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/session"
)

// GovernancePipeline orchestrates all governance checks.
// This is the single source of truth for governance logic.
// Adapters call PreExecute() and PostExecute(), then translate
// the structured results into framework-specific formats.
type GovernancePipeline struct {
	provider ContractProvider
}

// New creates a GovernancePipeline backed by the given ContractProvider.
func New(provider ContractProvider) *GovernancePipeline {
	return &GovernancePipeline{provider: provider}
}

// PreExecute runs all pre-execution governance checks.
func (p *GovernancePipeline) PreExecute(
	ctx context.Context,
	env *envelope.ToolEnvelope,
	sess *session.Session,
) (PreDecision, error) {
	hooks := make([]map[string]any, 0)
	contracts := make([]map[string]any, 0)
	hasObservedDeny := false
	limits := p.provider.GetLimits()

	// Pre-fetch session counters in a single batch.
	var includeTool string
	if _, ok := limits.MaxCallsPerTool[env.ToolName()]; ok {
		includeTool = env.ToolName()
	}
	counters, err := sess.BatchGetCounters(ctx, includeTool)
	if err != nil {
		return PreDecision{}, fmt.Errorf("batch counter fetch: %w", err)
	}

	// 1. Attempt limit
	if counters["attempts"] >= limits.MaxAttempts {
		return PreDecision{
			Action:             "deny",
			Reason:             fmt.Sprintf("Attempt limit reached (%d). Agent may be stuck in a retry loop. Stop and reassess.", limits.MaxAttempts),
			DecisionSource:     "attempt_limit",
			DecisionName:       "max_attempts",
			HooksEvaluated:     hooks,
			ContractsEvaluated: contracts,
		}, nil
	}

	// 2. Before hooks
	for _, hook := range p.provider.GetHooks("before", env) {
		if hook.When != nil && !hook.When(ctx, env) {
			continue
		}
		decision, hookErr := hook.Before(ctx, env)
		if hookErr != nil {
			log.Printf("Hook %s raised: %v", hook.HookName(), hookErr)
			decision = DenyHook(fmt.Sprintf("Hook error: %s", hookErr))
		}
		hookRecord := map[string]any{
			"name":   hook.HookName(),
			"result": string(decision.Result),
			"reason": decision.Reason,
		}
		hooks = append(hooks, hookRecord)
		if decision.Result == HookResultDeny {
			pe := false
			if decision.Reason != "" && len(decision.Reason) > 11 &&
				decision.Reason[:11] == "Hook error:" {
				pe = true
			}
			return PreDecision{
				Action:             "deny",
				Reason:             decision.Reason,
				DecisionSource:     "hook",
				DecisionName:       hook.HookName(),
				HooksEvaluated:     hooks,
				ContractsEvaluated: contracts,
				PolicyError:        pe,
			}, nil
		}
	}

	// 3. Preconditions
	deny, done := p.evalPreconditions(ctx, env, p.provider.GetPreconditions(env),
		"precondition", hooks, &contracts, &hasObservedDeny)
	if done {
		return deny, nil
	}

	// 3.5. Sandbox contracts
	deny, done = p.evalPreconditions(ctx, env, p.provider.GetSandboxContracts(env),
		"yaml_sandbox", hooks, &contracts, &hasObservedDeny)
	if done {
		return deny, nil
	}

	// 4. Session contracts
	for _, sc := range p.provider.GetSessionContracts() {
		verdict, scErr := sc.Check(ctx, sess)
		if scErr != nil {
			log.Printf("Session contract %s raised: %v", contractName(sc.Name), scErr)
			verdict = contract.Fail(
				fmt.Sprintf("Session contract error: %s", scErr),
				map[string]any{"policy_error": true},
			)
		}
		record := map[string]any{
			"name":    contractName(sc.Name),
			"type":    "session_contract",
			"passed":  verdict.Passed(),
			"message": verdict.Message(),
		}
		if verdict.Metadata() != nil {
			record["metadata"] = verdict.Metadata()
		}
		contracts = append(contracts, record)
		if !verdict.Passed() {
			source := sc.Source
			if source == "" {
				source = "session_contract"
			}
			return PreDecision{
				Action:             "deny",
				Reason:             verdict.Message(),
				DecisionSource:     source,
				DecisionName:       contractName(sc.Name),
				HooksEvaluated:     hooks,
				ContractsEvaluated: contracts,
				PolicyError:        hasPolicyError(contracts),
			}, nil
		}
	}

	// 5. Execution limits
	if counters["execs"] >= limits.MaxToolCalls {
		return PreDecision{
			Action:             "deny",
			Reason:             fmt.Sprintf("Execution limit reached (%d calls). Summarize progress and stop.", limits.MaxToolCalls),
			DecisionSource:     "operation_limit",
			DecisionName:       "max_tool_calls",
			HooksEvaluated:     hooks,
			ContractsEvaluated: contracts,
		}, nil
	}

	// Per-tool limits
	if toolLimit, ok := limits.MaxCallsPerTool[env.ToolName()]; ok {
		toolKey := "tool:" + env.ToolName()
		toolCount := counters[toolKey]
		if toolCount >= toolLimit {
			return PreDecision{
				Action:             "deny",
				Reason:             fmt.Sprintf("Per-tool limit: %s called %d times (limit: %d).", env.ToolName(), toolCount, toolLimit),
				DecisionSource:     "operation_limit",
				DecisionName:       "max_calls_per_tool:" + env.ToolName(),
				HooksEvaluated:     hooks,
				ContractsEvaluated: contracts,
			}, nil
		}
	}

	// 6. All checks passed
	// 7. Evaluate observe-mode contracts
	observeResults := p.evaluateObserveContracts(ctx, env, sess)

	return PreDecision{
		Action:             "allow",
		HooksEvaluated:     hooks,
		ContractsEvaluated: contracts,
		Observed:           hasObservedDeny,
		PolicyError:        hasPolicyError(contracts),
		ObserveResults:     observeResults,
	}, nil
}
