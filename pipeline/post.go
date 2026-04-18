package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// PostExecute runs all post-execution checks.
func (p *CheckPipeline) PostExecute(
	ctx context.Context,
	env toolcall.ToolCall,
	toolResponse any,
	toolSuccess bool,
) (PostDecision, error) {
	var warnings []string
	rules := make([]map[string]any, 0)
	var redactedResponse any
	outputSuppressed := false

	// 1. Postconditions
	for _, c := range p.provider.GetPostconditions(env) {
		// When predicate: skip this rule if When returns false
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		decision, err := c.Check(ctx, env, toolResponse)
		if err != nil {
			log.Printf("Postcondition %s raised: %v", ruleName(c.Name), err)
			decision = rule.Fail(
				fmt.Sprintf("Postcondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}

		record := map[string]any{
			"name":    ruleName(c.Name),
			"type":    "postcondition",
			"passed":  decision.Passed(),
			"message": decision.Message(),
		}
		if decision.Metadata() != nil {
			record["metadata"] = decision.Metadata()
		}
		rules = append(rules, record)

		if !decision.Passed() {
			effect := c.Effect
			if effect == "" {
				effect = "warn"
			}
			isSafe := env.SideEffect() == toolcall.SideEffectPure ||
				env.SideEffect() == toolcall.SideEffectRead

			switch {
			case c.Mode == "observe":
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f [observe] %s", decision.Message()))
			case effect == "redact" && isSafe:
				source := redactedResponse
				if source == nil {
					source = toolResponse
				}
				text := fmt.Sprintf("%v", source)
				if len(c.RedactPatterns) > 0 {
					for _, pat := range c.RedactPatterns {
						text = pat.ReplaceAllString(text, "[REDACTED]")
					}
				} else {
					text = "[REDACTED]"
				}
				redactedResponse = text
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f Content redacted by %s.", ruleName(c.Name)))
			case effect == "block" && isSafe:
				redactedResponse = fmt.Sprintf("[OUTPUT SUPPRESSED] %s", decision.Message())
				outputSuppressed = true
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f Output suppressed by %s.", ruleName(c.Name)))
			case (effect == "redact" || effect == "block") && !isSafe:
				log.Printf("Postcondition %s declares effect=%s but tool %s has side_effect=%s; falling back to warn.",
					ruleName(c.Name), effect, env.ToolName(), env.SideEffect())
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f %s Tool already executed \u2014 assess before proceeding.", decision.Message()))
			case isSafe:
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f %s Consider retrying.", decision.Message()))
			default:
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f %s Tool already executed \u2014 assess before proceeding.", decision.Message()))
			}
		}
	}

	// 2. After hooks
	for _, hook := range p.provider.GetHooks("after", env) {
		if hook.When != nil && !hook.When(ctx, env) {
			continue
		}
		if hook.After != nil {
			if err := hook.After(ctx, env, toolResponse); err != nil {
				log.Printf("After hook %s raised: %v", hook.HookName(), err)
			}
		}
	}

	// 3. Observe-mode postconditions (never affect real decision)
	for _, c := range p.provider.GetObservePostconditions(env) {
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		decision, err := c.Check(ctx, env, toolResponse)
		if err != nil {
			log.Printf("Observe-mode postcondition %s raised: %v",
				ruleName(c.Name), err)
			decision = rule.Fail(
				fmt.Sprintf("Observe-mode postcondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		record := map[string]any{
			"name":     ruleName(c.Name),
			"type":     "postcondition",
			"passed":   decision.Passed(),
			"message":  decision.Message(),
			"observed": true,
		}
		rules = append(rules, record)
		if !decision.Passed() {
			warnings = append(warnings,
				fmt.Sprintf("\u26a0\ufe0f [observe] %s", decision.Message()))
		}
	}

	postconditionsPassed := true
	for _, c := range rules {
		if passed, ok := c["passed"].(bool); ok && !passed {
			postconditionsPassed = false
			break
		}
	}

	return PostDecision{
		ToolSuccess:          toolSuccess,
		PostconditionsPassed: postconditionsPassed,
		Warnings:             warnings,
		RulesEvaluated:       rules,
		PolicyError:          hasPolicyError(rules),
		RedactedResponse:     redactedResponse,
		OutputSuppressed:     outputSuppressed,
	}, nil
}
