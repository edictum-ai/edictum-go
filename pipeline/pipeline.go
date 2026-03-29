package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// CheckPipeline orchestrates all governance checks.
// This is the single source of truth for governance logic.
// Adapters call PreExecute() and PostExecute(), then translate
// the structured results into framework-specific formats.
type CheckPipeline struct {
	provider RuleProvider
}

// New creates a CheckPipeline backed by the given RuleProvider.
func New(provider RuleProvider) *CheckPipeline {
	return &CheckPipeline{provider: provider}
}

// PreExecute runs all pre-execution governance checks.
func (p *CheckPipeline) PreExecute(
	ctx context.Context,
	env toolcall.ToolCall,
	sess *session.Session,
) (PreDecision, error) {
	hooks := make([]map[string]any, 0)
	rules := make([]map[string]any, 0)
	hasObservedDeny := false
	limits := p.provider.GetLimits()
	var workflowMeta map[string]any
	var workflowStageID string
	workflowInvolved := false

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
	// NOTE: attempts is pre-incremented in guard.Run() before this check.
	// With max_attempts=N, exactly N calls are allowed before denial.
	// This matches Python parity: increment_attempts() before pre_execute().
	if counters["attempts"] >= limits.MaxAttempts {
		return PreDecision{
			Action:           "block",
			Reason:           fmt.Sprintf("Attempt limit reached (%d). Agent may be stuck in a retry loop. Stop and reassess.", limits.MaxAttempts),
			DecisionSource:   "attempt_limit",
			DecisionName:     "max_attempts",
			HooksEvaluated:   hooks,
			RulesEvaluated:   rules,
			Workflow:         workflowMeta,
			WorkflowStageID:  workflowStageID,
			WorkflowInvolved: workflowInvolved,
		}, nil
	}

	// 2. Before hooks
	for _, hook := range p.provider.GetHooks("before", env) {
		if hook.When != nil && !hook.When(ctx, env) {
			continue
		}
		hookRaisedException := false
		decision, hookErr := hook.Before(ctx, env)
		if hookErr != nil {
			log.Printf("Hook %s raised: %v", hook.HookName(), hookErr)
			decision = BlockHook(fmt.Sprintf("Hook error: %s", hookErr))
			hookRaisedException = true
		}
		hookRecord := map[string]any{
			"name":   hook.HookName(),
			"result": string(decision.Result),
			"reason": decision.Reason,
		}
		hooks = append(hooks, hookRecord)
		if decision.Result == HookResultBlock {
			return PreDecision{
				Action:           "block",
				Reason:           decision.Reason,
				DecisionSource:   "hook",
				DecisionName:     hook.HookName(),
				HooksEvaluated:   hooks,
				RulesEvaluated:   rules,
				PolicyError:      hookRaisedException,
				Workflow:         workflowMeta,
				WorkflowStageID:  workflowStageID,
				WorkflowInvolved: workflowInvolved,
			}, nil
		}
	}

	// 3. Preconditions
	deny, done := p.evalPreconditions(ctx, env, p.provider.GetPreconditions(env),
		"precondition", hooks, &rules, &hasObservedDeny)
	if done {
		return deny, nil
	}

	// 3.5. Sandbox rules
	deny, done = p.evalPreconditions(ctx, env, p.provider.GetSandboxRules(env),
		"yaml_sandbox", hooks, &rules, &hasObservedDeny)
	if done {
		return deny, nil
	}

	// 4. Session rules
	for _, sc := range p.provider.GetSessionRules() {
		decision, scErr := sc.Check(ctx, sess)
		if scErr != nil {
			log.Printf("Session rule %s raised: %v", ruleName(sc.Name), scErr)
			decision = rule.Fail(
				fmt.Sprintf("Session rule error: %s", scErr),
				map[string]any{"policy_error": true},
			)
		}
		record := map[string]any{
			"name":    ruleName(sc.Name),
			"type":    "session_rule",
			"passed":  decision.Passed(),
			"message": decision.Message(),
		}
		if decision.Metadata() != nil {
			record["metadata"] = decision.Metadata()
		}
		rules = append(rules, record)
		if !decision.Passed() {
			source := sc.Source
			if source == "" {
				source = "session_rule"
			}
			return PreDecision{
				Action:           "block",
				Reason:           decision.Message(),
				DecisionSource:   source,
				DecisionName:     ruleName(sc.Name),
				HooksEvaluated:   hooks,
				RulesEvaluated:   rules,
				PolicyError:      hasPolicyError(rules),
				Workflow:         workflowMeta,
				WorkflowStageID:  workflowStageID,
				WorkflowInvolved: workflowInvolved,
			}, nil
		}
	}

	// 5. Workflow gates
	if rt := p.provider.GetWorkflowRuntime(); rt != nil {
		wf, wfErr := rt.Evaluate(ctx, sess, env)
		if wfErr != nil {
			record := map[string]any{
				"name":    "workflow:error",
				"type":    "workflow_gate",
				"passed":  false,
				"message": fmt.Sprintf("Workflow evaluation error: %s", wfErr),
				"metadata": map[string]any{
					"policy_error": true,
				},
			}
			rules = append(rules, record)
			return PreDecision{
				Action:           "block",
				Reason:           record["message"].(string),
				DecisionSource:   "workflow",
				DecisionName:     "workflow_error",
				HooksEvaluated:   hooks,
				RulesEvaluated:   rules,
				PolicyError:      true,
				Workflow:         workflowMeta,
				WorkflowStageID:  workflowStageID,
				WorkflowInvolved: true,
			}, nil
		}
		if len(wf.Records) > 0 {
			rules = append(rules, wf.Records...)
			workflowInvolved = true
			workflowMeta = wf.Audit
			workflowStageID = wf.StageID
		}
		switch wf.Action {
		case "block":
			return PreDecision{
				Action:           "block",
				Reason:           wf.Reason,
				DecisionSource:   "workflow",
				DecisionName:     wf.StageID,
				HooksEvaluated:   hooks,
				RulesEvaluated:   rules,
				PolicyError:      hasPolicyError(rules),
				Workflow:         workflowMeta,
				WorkflowStageID:  workflowStageID,
				WorkflowInvolved: workflowInvolved,
			}, nil
		case "pending_approval":
			return PreDecision{
				Action:           "pending_approval",
				Reason:           wf.Reason,
				DecisionSource:   "workflow",
				DecisionName:     wf.StageID,
				HooksEvaluated:   hooks,
				RulesEvaluated:   rules,
				PolicyError:      hasPolicyError(rules),
				ApprovalMessage:  wf.Reason,
				Workflow:         workflowMeta,
				WorkflowStageID:  workflowStageID,
				WorkflowInvolved: workflowInvolved,
			}, nil
		}
	}

	// 6. Execution limits
	if counters["execs"] >= limits.MaxToolCalls {
		return PreDecision{
			Action:           "block",
			Reason:           fmt.Sprintf("Execution limit reached (%d calls). Summarize progress and stop.", limits.MaxToolCalls),
			DecisionSource:   "operation_limit",
			DecisionName:     "max_tool_calls",
			HooksEvaluated:   hooks,
			RulesEvaluated:   rules,
			Workflow:         workflowMeta,
			WorkflowStageID:  workflowStageID,
			WorkflowInvolved: workflowInvolved,
		}, nil
	}

	// Per-tool limits
	if toolLimit, ok := limits.MaxCallsPerTool[env.ToolName()]; ok {
		toolKey := "tool:" + env.ToolName()
		toolCount := counters[toolKey]
		if toolCount >= toolLimit {
			return PreDecision{
				Action:           "block",
				Reason:           fmt.Sprintf("Per-tool limit: %s called %d times (limit: %d).", env.ToolName(), toolCount, toolLimit),
				DecisionSource:   "operation_limit",
				DecisionName:     "max_calls_per_tool:" + env.ToolName(),
				HooksEvaluated:   hooks,
				RulesEvaluated:   rules,
				Workflow:         workflowMeta,
				WorkflowStageID:  workflowStageID,
				WorkflowInvolved: workflowInvolved,
			}, nil
		}
	}

	// 7. All checks passed
	// 8. Evaluate observe-mode rules
	observeResults := p.evaluateObserveContracts(ctx, env, sess)

	return PreDecision{
		Action:           "allow",
		HooksEvaluated:   hooks,
		RulesEvaluated:   rules,
		Observed:         hasObservedDeny,
		PolicyError:      hasPolicyError(rules),
		ObserveResults:   observeResults,
		Workflow:         workflowMeta,
		WorkflowStageID:  workflowStageID,
		WorkflowInvolved: workflowInvolved,
	}, nil
}
