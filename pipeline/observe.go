package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// evaluateObserveContracts evaluates observe-mode rules without
// affecting the real decision. Results are returned for audit emission.
func (p *CheckPipeline) evaluateObserveContracts(
	ctx context.Context,
	env toolcall.ToolCall,
	sess *session.Session,
) []map[string]any {
	// Pre-allocate results slice based on total observe rule count.
	observePres := p.provider.GetObservePreconditions(env)
	observeSandbox := p.provider.GetObserveSandboxContracts(env)
	observeSession := p.provider.GetObserveSessionRules()
	results := make([]map[string]any, 0, len(observePres)+len(observeSandbox)+len(observeSession))

	// Observe preconditions
	for _, c := range observePres {
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		decision, err := c.Check(ctx, env)
		if err != nil {
			log.Printf("Observe-mode precondition %s raised: %v", ruleName(c.Name), err)
			decision = rule.Fail(
				fmt.Sprintf("Observe-mode precondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		source := c.Source
		if source == "" {
			source = "yaml_precondition"
		}
		results = append(results, map[string]any{
			"name":    ruleName(c.Name),
			"type":    "precondition",
			"passed":  decision.Passed(),
			"message": decision.Message(),
			"source":  source,
		})
	}

	// Observe sandbox rules
	for _, c := range observeSandbox {
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		decision, err := c.Check(ctx, env)
		if err != nil {
			log.Printf("Observe-mode sandbox %s raised: %v", ruleName(c.Name), err)
			decision = rule.Fail(
				fmt.Sprintf("Observe-mode sandbox error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		source := c.Source
		if source == "" {
			source = "yaml_sandbox"
		}
		results = append(results, map[string]any{
			"name":    ruleName(c.Name),
			"type":    "sandbox",
			"passed":  decision.Passed(),
			"message": decision.Message(),
			"source":  source,
		})
	}

	// Observe session rules
	for _, sc := range observeSession {
		decision, err := sc.Check(ctx, sess)
		if err != nil {
			log.Printf("Observe-mode session rule %s raised: %v", ruleName(sc.Name), err)
			decision = rule.Fail(
				fmt.Sprintf("Observe-mode session rule error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		source := sc.Source
		if source == "" {
			source = "yaml_session"
		}
		results = append(results, map[string]any{
			"name":    ruleName(sc.Name),
			"type":    "session_rule",
			"passed":  decision.Passed(),
			"message": decision.Message(),
			"source":  source,
		})
	}

	return results
}
