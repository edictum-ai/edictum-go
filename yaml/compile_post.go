package yaml

import (
	"context"
	"fmt"
	"regexp"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func compilePost(
	raw map[string]any,
	mode string,
	cc *compileCtx,
) (rule.Postcondition, error) {
	cid, _ := raw["id"].(string)
	tool, _ := raw["tool"].(string)
	whenExpr, _ := raw["when"].(map[string]any)
	then, _ := raw["then"].(map[string]any)

	if whenExpr == nil || then == nil {
		return rule.Postcondition{}, fmt.Errorf("rule %q: missing when or then", cid)
	}

	compiled := precompileRegexes(whenExpr)
	msgTemplate, _ := then["message"].(string)
	effect, _ := then["action"].(string)
	if effect == "" {
		effect = "warn"
	}

	isObserve, _ := raw["_observe"].(bool)
	source := "yaml_postcondition"

	// Extract output.text regex patterns for redaction
	redactPatterns := extractOutputPatterns(compiled)

	post := rule.Postcondition{
		Name:           cid,
		Tool:           tool,
		Mode:           mode,
		Source:         source,
		Effect:         effect,
		RedactPatterns: redactPatterns,
		Check: func(_ context.Context, env toolcall.ToolCall, response any) (rule.Decision, error) {
			outputText := ""
			outputPresent := response != nil
			if response != nil {
				outputText = fmt.Sprintf("%v", response)
			}
			result := EvaluateExpression(compiled, env, outputText,
				WithCustomOperators(cc.customOperators),
				WithCustomSelectors(cc.customSelectors),
				withOutputPresent(outputPresent),
			)
			msg := expandMessage(msgTemplate, env, outputText, cc.customSelectors, outputPresent)
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
		post.Mode = "observe"
	}

	return post, nil
}

// extractOutputPatterns collects compiled regex patterns from output.text
// leaves in the expression tree for use in postcondition redaction.
func extractOutputPatterns(expr map[string]any) []*regexp.Regexp {
	var patterns []*regexp.Regexp
	walkOutputPatterns(expr, &patterns)
	return patterns
}

func walkOutputPatterns(expr map[string]any, out *[]*regexp.Regexp) {
	if subs, ok := expr["all"].([]any); ok {
		for _, sub := range subs {
			if m, ok := sub.(map[string]any); ok {
				walkOutputPatterns(m, out)
			}
		}
		return
	}
	if subs, ok := expr["any"].([]any); ok {
		for _, sub := range subs {
			if m, ok := sub.(map[string]any); ok {
				walkOutputPatterns(m, out)
			}
		}
		return
	}
	if sub, ok := expr["not"].(map[string]any); ok {
		walkOutputPatterns(sub, out)
		return
	}

	// Leaf: check for output.text with matches/matches_any
	op, ok := expr["output.text"].(map[string]any)
	if !ok {
		return
	}
	if re, ok := op["matches"].(*regexp.Regexp); ok {
		*out = append(*out, re)
	}
	if pats, ok := op["matches_any"].([]any); ok {
		for _, p := range pats {
			if re, ok := p.(*regexp.Regexp); ok {
				*out = append(*out, re)
			}
		}
	}
}
