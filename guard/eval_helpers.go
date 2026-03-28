package guard

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func evalPrecondition(
	ctx context.Context,
	c rule.Precondition,
	env2 toolcall.ToolCall,
	ruleType string,
	rules *[]RuleResult,
	denyReasons *[]string,
) {
	name := c.Name
	if name == "" {
		name = "anonymous"
	}

	// When predicate: skip if false
	if c.When != nil && !c.When(ctx, env2) {
		return
	}

	decision, err := c.Check(ctx, env2)
	if err != nil {
		log.Printf("Rule %s raised: %v", name, err)
		cr := RuleResult{
			RuleID:      name,
			RuleType:    ruleType,
			Passed:      false,
			Message:     fmt.Sprintf("Precondition error: %s", err),
			PolicyError: true,
		}
		*rules = append(*rules, cr)
		*denyReasons = append(*denyReasons, cr.Message)
		return
	}

	isObserved := c.Mode == "observe" && !decision.Passed()
	pe := false
	if m := decision.Metadata(); m != nil {
		if v, ok := m["policy_error"].(bool); ok && v {
			pe = true
		}
	}

	cr := RuleResult{
		RuleID:      name,
		RuleType:    ruleType,
		Passed:      decision.Passed(),
		Message:     decision.Message(),
		Observed:    isObserved,
		PolicyError: pe,
	}
	*rules = append(*rules, cr)
	if !decision.Passed() && !isObserved {
		*denyReasons = append(*denyReasons, decision.Message())
	}
}

func evalPostcondition(
	ctx context.Context,
	c rule.Postcondition,
	env2 toolcall.ToolCall,
	output string,
	rules *[]RuleResult,
	warnReasons *[]string,
) {
	name := c.Name
	if name == "" {
		name = "anonymous"
	}

	// When predicate: skip if false
	if c.When != nil && !c.When(ctx, env2) {
		return
	}

	decision, err := c.Check(ctx, env2, output)
	if err != nil {
		log.Printf("Postcondition %s raised: %v", name, err)
		cr := RuleResult{
			RuleID:      name,
			RuleType:    "postcondition",
			Passed:      false,
			Message:     fmt.Sprintf("Postcondition error: %s", err),
			PolicyError: true,
		}
		*rules = append(*rules, cr)
		*warnReasons = append(*warnReasons, cr.Message)
		return
	}

	isObserved := c.Mode == "observe" && !decision.Passed()
	pe := false
	if m := decision.Metadata(); m != nil {
		if v, ok := m["policy_error"].(bool); ok && v {
			pe = true
		}
	}

	effect := c.Effect
	if effect == "" {
		effect = "warn"
	}

	cr := RuleResult{
		RuleID:      name,
		RuleType:    "postcondition",
		Passed:      decision.Passed(),
		Message:     decision.Message(),
		Observed:    isObserved,
		Effect:      effect,
		PolicyError: pe,
	}
	*rules = append(*rules, cr)
	if !decision.Passed() && !isObserved {
		*warnReasons = append(*warnReasons, decision.Message())
	}
}
