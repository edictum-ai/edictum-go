package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/session"
)

// evaluateObserveContracts evaluates observe-mode contracts without
// affecting the real decision. Results are returned for audit emission.
func (p *GovernancePipeline) evaluateObserveContracts(
	ctx context.Context,
	env envelope.ToolEnvelope,
	sess *session.Session,
) []map[string]any {
	// Pre-allocate results slice based on total observe contract count.
	shadowPres := p.provider.GetObservePreconditions(env)
	shadowSandbox := p.provider.GetObserveSandboxContracts(env)
	shadowSession := p.provider.GetObserveSessionContracts()
	results := make([]map[string]any, 0, len(shadowPres)+len(shadowSandbox)+len(shadowSession))

	// Observe preconditions
	for _, c := range shadowPres {
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		verdict, err := c.Check(ctx, env)
		if err != nil {
			log.Printf("Observe-mode precondition %s raised: %v", contractName(c.Name), err)
			verdict = contract.Fail(
				fmt.Sprintf("Observe-mode precondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		source := c.Source
		if source == "" {
			source = "yaml_precondition"
		}
		results = append(results, map[string]any{
			"name":    contractName(c.Name),
			"type":    "precondition",
			"passed":  verdict.Passed(),
			"message": verdict.Message(),
			"source":  source,
		})
	}

	// Observe sandbox contracts
	for _, c := range shadowSandbox {
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		verdict, err := c.Check(ctx, env)
		if err != nil {
			log.Printf("Observe-mode sandbox %s raised: %v", contractName(c.Name), err)
			verdict = contract.Fail(
				fmt.Sprintf("Observe-mode sandbox error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		source := c.Source
		if source == "" {
			source = "yaml_sandbox"
		}
		results = append(results, map[string]any{
			"name":    contractName(c.Name),
			"type":    "sandbox",
			"passed":  verdict.Passed(),
			"message": verdict.Message(),
			"source":  source,
		})
	}

	// Observe session contracts
	for _, sc := range shadowSession {
		verdict, err := sc.Check(ctx, sess)
		if err != nil {
			log.Printf("Observe-mode session contract %s raised: %v", contractName(sc.Name), err)
			verdict = contract.Fail(
				fmt.Sprintf("Observe-mode session contract error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		source := sc.Source
		if source == "" {
			source = "yaml_session"
		}
		results = append(results, map[string]any{
			"name":    contractName(sc.Name),
			"type":    "session_contract",
			"passed":  verdict.Passed(),
			"message": verdict.Message(),
			"source":  source,
		})
	}

	return results
}
