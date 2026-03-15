package pipeline

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

// evalPreconditions evaluates a slice of preconditions (or sandbox contracts).
// Returns (decision, true) if a deny/approval was triggered; (zero, false) otherwise.
func (p *GovernancePipeline) evalPreconditions(
	ctx context.Context,
	env envelope.ToolEnvelope,
	pres []contract.Precondition,
	defaultSource string,
	hooks []map[string]any,
	contracts *[]map[string]any,
	hasObservedDeny *bool,
) (PreDecision, bool) {
	for _, c := range pres {
		// When predicate: skip this contract if When returns false
		if c.When != nil && !c.When(ctx, env) {
			continue
		}
		verdict, err := c.Check(ctx, env)
		if err != nil {
			log.Printf("Contract %s raised: %v", contractName(c.Name), err)
			verdict = contract.Fail(
				fmt.Sprintf("Precondition error: %s", err),
				map[string]any{"policy_error": true},
			)
		}
		record := map[string]any{
			"name":    contractName(c.Name),
			"type":    contractType(defaultSource),
			"passed":  verdict.Passed(),
			"message": verdict.Message(),
		}
		if verdict.Metadata() != nil {
			record["metadata"] = verdict.Metadata()
		}
		*contracts = append(*contracts, record)

		if !verdict.Passed() {
			if c.Mode == "observe" {
				record["observed"] = true
				*hasObservedDeny = true
				continue
			}
			source := c.Source
			if source == "" {
				source = defaultSource
			}
			pe := hasPolicyError(*contracts)
			effect := c.Effect
			if effect == "" {
				effect = "deny"
			}
			if effect == "approve" {
				timeout := c.Timeout
				if timeout == 0 {
					timeout = 300
				}
				timeoutEff := c.TimeoutEffect
				if timeoutEff == "" {
					timeoutEff = "deny"
				}
				return PreDecision{
					Action:             "pending_approval",
					Reason:             verdict.Message(),
					DecisionSource:     source,
					DecisionName:       contractName(c.Name),
					HooksEvaluated:     hooks,
					ContractsEvaluated: *contracts,
					PolicyError:        pe,
					ApprovalTimeout:    timeout,
					ApprovalTimeoutEff: timeoutEff,
					ApprovalMessage:    verdict.Message(),
				}, true
			}
			return PreDecision{
				Action:             "deny",
				Reason:             verdict.Message(),
				DecisionSource:     source,
				DecisionName:       contractName(c.Name),
				HooksEvaluated:     hooks,
				ContractsEvaluated: *contracts,
				PolicyError:        pe,
			}, true
		}
	}
	return PreDecision{}, false
}

func contractName(name string) string {
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

func hasPolicyError(contracts []map[string]any) bool {
	for _, c := range contracts {
		if meta, ok := c["metadata"].(map[string]any); ok {
			if pe, ok := meta["policy_error"].(bool); ok && pe {
				return true
			}
		}
	}
	return false
}
