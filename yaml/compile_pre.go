package yaml

import (
	"context"
	"fmt"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

func compilePre(
	raw map[string]any,
	mode string,
	cc *compileCtx,
) (contract.Precondition, error) {
	cid, _ := raw["id"].(string)
	tool, _ := raw["tool"].(string)
	whenExpr, _ := raw["when"].(map[string]any)
	then, _ := raw["then"].(map[string]any)

	if whenExpr == nil || then == nil {
		return contract.Precondition{}, fmt.Errorf("contract %q: missing when or then", cid)
	}

	compiled := precompileRegexes(whenExpr)
	msgTemplate, _ := then["message"].(string)
	effect, _ := then["effect"].(string)
	if effect == "" {
		effect = "deny"
	}
	timeout := intOr(then["timeout"], 300)
	timeoutEffect, _ := then["timeout_effect"].(string)
	if timeoutEffect == "" {
		timeoutEffect = "deny"
	}

	isObserve, _ := raw["_observe"].(bool)
	source := "yaml_precondition"

	pre := contract.Precondition{
		Name:          cid,
		Tool:          tool,
		Mode:          mode,
		Source:        source,
		Effect:        effect,
		Timeout:       timeout,
		TimeoutEffect: timeoutEffect,
		Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
			result := EvaluateExpression(compiled, env, "",
				WithCustomOperators(cc.customOperators),
				WithCustomSelectors(cc.customSelectors),
			)
			if result.PolicyError {
				return contract.Fail(msgTemplate, map[string]any{
					"policy_error": true,
				}), nil
			}
			if result.Matched {
				return contract.Fail(msgTemplate), nil
			}
			return contract.Pass(), nil
		},
	}

	if isObserve {
		pre.Mode = "observe"
	}

	return pre, nil
}

func intOr(v any, fallback int) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	default:
		return fallback
	}
}
