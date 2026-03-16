package yaml

import "regexp"

// precompileRegexes walks an expression tree and compiles regex
// patterns under matches/matches_any into *regexp.Regexp objects
// so the evaluator never recompiles per-call.
func precompileRegexes(expr map[string]any) map[string]any {
	if expr == nil {
		return nil
	}

	if subs, ok := expr["all"].([]any); ok {
		out := make([]any, len(subs))
		for i, sub := range subs {
			if m, ok := sub.(map[string]any); ok {
				out[i] = precompileRegexes(m)
			} else {
				out[i] = sub
			}
		}
		return map[string]any{"all": out}
	}
	if subs, ok := expr["any"].([]any); ok {
		out := make([]any, len(subs))
		for i, sub := range subs {
			if m, ok := sub.(map[string]any); ok {
				out[i] = precompileRegexes(m)
			} else {
				out[i] = sub
			}
		}
		return map[string]any{"any": out}
	}
	if sub, ok := expr["not"].(map[string]any); ok {
		return map[string]any{"not": precompileRegexes(sub)}
	}

	// Leaf node: selector → operator block
	compiled := make(map[string]any, len(expr))
	for selector, opBlock := range expr {
		op, ok := opBlock.(map[string]any)
		if !ok {
			compiled[selector] = opBlock
			continue
		}
		newOp := make(map[string]any, len(op))
		for k, v := range op {
			newOp[k] = v
		}
		if pat, ok := newOp["matches"].(string); ok {
			if re, err := regexp.Compile(pat); err == nil {
				newOp["matches"] = re
			}
		}
		if pats, ok := newOp["matches_any"].([]any); ok {
			reList := make([]any, len(pats))
			for i, p := range pats {
				if s, ok := p.(string); ok {
					if re, err := regexp.Compile(s); err == nil {
						reList[i] = re
					} else {
						reList[i] = p
					}
				} else {
					reList[i] = p
				}
			}
			newOp["matches_any"] = reList
		}
		compiled[selector] = newOp
	}
	return compiled
}
