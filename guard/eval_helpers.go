package guard

import (
	"context"
	"fmt"
	"log"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

func evalPrecondition(
	ctx context.Context,
	c contract.Precondition,
	env2 envelope.ToolEnvelope,
	contractType string,
	contracts *[]ContractResult,
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

	verdict, err := c.Check(ctx, env2)
	if err != nil {
		log.Printf("Contract %s raised: %v", name, err)
		cr := ContractResult{
			ContractID:   name,
			ContractType: contractType,
			Passed:       false,
			Message:      fmt.Sprintf("Precondition error: %s", err),
			PolicyError:  true,
		}
		*contracts = append(*contracts, cr)
		*denyReasons = append(*denyReasons, cr.Message)
		return
	}

	isObserved := c.Mode == "observe" && !verdict.Passed()
	pe := false
	if m := verdict.Metadata(); m != nil {
		if v, ok := m["policy_error"].(bool); ok && v {
			pe = true
		}
	}

	cr := ContractResult{
		ContractID:   name,
		ContractType: contractType,
		Passed:       verdict.Passed(),
		Message:      verdict.Message(),
		Observed:     isObserved,
		PolicyError:  pe,
	}
	*contracts = append(*contracts, cr)
	if !verdict.Passed() && !isObserved {
		*denyReasons = append(*denyReasons, verdict.Message())
	}
}

func evalPostcondition(
	ctx context.Context,
	c contract.Postcondition,
	env2 envelope.ToolEnvelope,
	output string,
	contracts *[]ContractResult,
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

	verdict, err := c.Check(ctx, env2, output)
	if err != nil {
		log.Printf("Postcondition %s raised: %v", name, err)
		cr := ContractResult{
			ContractID:   name,
			ContractType: "postcondition",
			Passed:       false,
			Message:      fmt.Sprintf("Postcondition error: %s", err),
			PolicyError:  true,
		}
		*contracts = append(*contracts, cr)
		*warnReasons = append(*warnReasons, cr.Message)
		return
	}

	isObserved := c.Mode == "observe" && !verdict.Passed()
	pe := false
	if m := verdict.Metadata(); m != nil {
		if v, ok := m["policy_error"].(bool); ok && v {
			pe = true
		}
	}

	effect := c.Effect
	if effect == "" {
		effect = "warn"
	}

	cr := ContractResult{
		ContractID:   name,
		ContractType: "postcondition",
		Passed:       verdict.Passed(),
		Message:      verdict.Message(),
		Observed:     isObserved,
		Effect:       effect,
		PolicyError:  pe,
	}
	*contracts = append(*contracts, cr)
	if !verdict.Passed() && !isObserved {
		*warnReasons = append(*warnReasons, verdict.Message())
	}
}
