package yaml

import (
	"context"
	"fmt"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func compilePre(
	raw map[string]any,
	mode string,
	cc *compileCtx,
) (rule.Precondition, error) {
	cid, _ := raw["id"].(string)
	tool, _ := raw["tool"].(string)
	whenExpr, _ := raw["when"].(map[string]any)
	then, _ := raw["then"].(map[string]any)

	if whenExpr == nil || then == nil {
		return rule.Precondition{}, fmt.Errorf("rule %q: missing when or then", cid)
	}

	compiled := precompileRegexes(whenExpr)
	msgTemplate, _ := then["message"].(string)
	effect, _ := then["action"].(string)
	if effect == "" {
		effect = "block"
	}
	timeout := intOr(then["timeout"], 300)
	timeoutEffect, _ := then["timeout_action"].(string)
	if timeoutEffect == "" {
		timeoutEffect = "block"
	}

	isObserve, _ := raw["_observe"].(bool)
	source := "yaml_precondition"

	pre := rule.Precondition{
		Name:          cid,
		Tool:          tool,
		Mode:          mode,
		Source:        source,
		Effect:        effect,
		Timeout:       timeout,
		TimeoutEffect: timeoutEffect,
		Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
			result := EvaluateExpression(compiled, env, "",
				WithCustomOperators(cc.customOperators),
				WithCustomSelectors(cc.customSelectors),
				withOutputPresent(false),
			)
			msg := expandMessage(msgTemplate, env, "", cc.customSelectors, false)
			if result.PolicyError {
				return rule.Fail(msg, map[string]any{
					"policy_error": true,
				}), nil
			}
			if result.Matched {
				return rule.Fail(msg), nil
			}
			return rule.Pass(), nil
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
