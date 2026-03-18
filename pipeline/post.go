package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

// PostExecute runs all post-execution governance checks.
func (p *GovernancePipeline) PostExecute(
	ctx context.Context,
	env envelope.ToolEnvelope,
	toolResponse any,
	toolSuccess bool,
) (PostDecision, error) {
	var warnings []string
	contracts := make([]map[string]any, 0)
	var redactedResponse any
	outputSuppressed := false

	// 1. Postconditions
	for _, c := range p.provider.GetPostconditions(env) {
		// When predicate: skip this contract if When returns false
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		verdict, err := c.Check(ctx, env, toolResponse)
		if err != nil {
			log.Printf("Postcondition %s raised: %v", contractName(c.Name), err)
			verdict = contract.Fail(
				fmt.Sprintf("Postcondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}

		record := map[string]any{
			"name":    contractName(c.Name),
			"type":    "postcondition",
			"passed":  verdict.Passed(),
			"message": verdict.Message(),
		}
		if verdict.Metadata() != nil {
			record["metadata"] = verdict.Metadata()
		}
		contracts = append(contracts, record)

		if !verdict.Passed() {
			effect := c.Effect
			if effect == "" {
				effect = "warn"
			}
			isSafe := env.SideEffect() == envelope.SideEffectPure ||
				env.SideEffect() == envelope.SideEffectRead

			switch {
			case c.Mode == "observe":
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f [observe] %s", verdict.Message()))
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
					fmt.Sprintf("\u26a0\ufe0f Content redacted by %s.", contractName(c.Name)))
			case effect == "deny" && isSafe:
				redactedResponse = fmt.Sprintf("[OUTPUT SUPPRESSED] %s", verdict.Message())
				outputSuppressed = true
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f Output suppressed by %s.", contractName(c.Name)))
			case (effect == "redact" || effect == "deny") && !isSafe:
				log.Printf("Postcondition %s declares effect=%s but tool %s has side_effect=%s; falling back to warn.",
					contractName(c.Name), effect, env.ToolName(), env.SideEffect())
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f %s Tool already executed \u2014 assess before proceeding.", verdict.Message()))
			case isSafe:
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f %s Consider retrying.", verdict.Message()))
			default:
				warnings = append(warnings,
					fmt.Sprintf("\u26a0\ufe0f %s Tool already executed \u2014 assess before proceeding.", verdict.Message()))
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
		verdict, err := c.Check(ctx, env, toolResponse)
		if err != nil {
			log.Printf("Observe-mode postcondition %s raised: %v",
				contractName(c.Name), err)
			verdict = contract.Fail(
				fmt.Sprintf("Observe-mode postcondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		record := map[string]any{
			"name":     contractName(c.Name),
			"type":     "postcondition",
			"passed":   verdict.Passed(),
			"message":  verdict.Message(),
			"observed": true,
		}
		contracts = append(contracts, record)
		if !verdict.Passed() {
			warnings = append(warnings,
				fmt.Sprintf("\u26a0\ufe0f [observe] %s", verdict.Message()))
		}
	}

	postconditionsPassed := true
	for _, c := range contracts {
		if passed, ok := c["passed"].(bool); ok && !passed {
			postconditionsPassed = false
			break
		}
	}

	return PostDecision{
		ToolSuccess:          toolSuccess,
		PostconditionsPassed: postconditionsPassed,
		Warnings:             warnings,
		ContractsEvaluated:   contracts,
		PolicyError:          hasPolicyError(contracts),
		RedactedResponse:     redactedResponse,
		OutputSuppressed:     outputSuppressed,
	}, nil
}
