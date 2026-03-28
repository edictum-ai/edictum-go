package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// evalPreconditions evaluates a slice of preconditions (or sandbox rules).
// Returns (decision, true) if a deny/approval was triggered; (zero, false) otherwise.
func (p *CheckPipeline) evalPreconditions(
	ctx context.Context,
	env toolcall.ToolCall,
	pres []rule.Precondition,
	defaultSource string,
	hooks []map[string]any,
	rules *[]map[string]any,
	hasObservedDeny *bool,
) (PreDecision, bool) {
	for _, c := range pres {
		// When predicate: skip this rule if When returns false
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		decision, err := c.Check(ctx, env)
		if err != nil {
			log.Printf("Rule %s raised: %v", ruleName(c.Name), err)
			decision = rule.Fail(
				fmt.Sprintf("Precondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		record := map[string]any{
			"name":    ruleName(c.Name),
			"type":    contractType(defaultSource),
			"passed":  decision.Passed(),
			"message": decision.Message(),
		}
		if decision.Metadata() != nil {
			record["metadata"] = decision.Metadata()
		}
		*rules = append(*rules, record)

		if !decision.Passed() {
			if c.Mode == "observe" {
				record["observed"] = true
				*hasObservedDeny = true
				continue
			}
			source := c.Source
			if source == "" {
				source = defaultSource
			}
			pe := hasPolicyError(*rules)
			effect := c.Effect
			if effect == "" {
				effect = "block"
			}
			if effect == "ask" {
				timeout := c.Timeout
				if timeout == 0 {
					timeout = 300
				}
				timeoutEff := c.TimeoutEffect
				if timeoutEff == "" {
					timeoutEff = "block"
				}
				return PreDecision{
					Action:             "pending_approval",
					Reason:             decision.Message(),
					DecisionSource:     source,
					DecisionName:       ruleName(c.Name),
					HooksEvaluated:     hooks,
					RulesEvaluated:     *rules,
					PolicyError:        pe,
					ApprovalTimeout:    timeout,
					ApprovalTimeoutEff: timeoutEff,
					ApprovalMessage:    decision.Message(),
				}, true
			}
			return PreDecision{
				Action:         "block",
				Reason:         decision.Message(),
				DecisionSource: source,
				DecisionName:   ruleName(c.Name),
				HooksEvaluated: hooks,
				RulesEvaluated: *rules,
				PolicyError:    pe,
			}, true
		}
	}
	return PreDecision{}, false
}

func ruleName(name string) string {
	if name != "" {
		return name
	}
	return "anonymous"
}

func contractType(source string) string {
	switch source {
	case "yaml_sandbox":
		return "sandbox"
	default:
		return "precondition"
	}
}

func hasPolicyError(rules []map[string]any) bool {
	for _, c := range rules {
		if meta, ok := c["metadata"].(map[string]any); ok {
			if pe, ok := meta["policy_error"].(bool); ok && pe {
				return true
			}
		}
	}
	return false
}
