package yaml

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed edictum-v1.schema.json
var bundleSchema string

var schemaLoader = gojsonschema.NewStringLoader(bundleSchema)

// validateSchema applies the canonical Python JSON Schema first, then
// preserves Go-specific reserved-key checks.
func validateSchema(data map[string]any) error {
	result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewGoLoader(data))
	if err != nil {
		return fmt.Errorf("yaml: schema validation failed: %w", err)
	}
	if !result.Valid() {
		return fmt.Errorf("yaml: schema validation failed: %s", schemaErrors(result.Errors()))
	}

	contracts, _ := data["contracts"].([]any)
	for i, c := range contracts {
		cm, ok := c.(map[string]any)
		if !ok {
			return fmt.Errorf("yaml: contract at index %d must be a mapping", i)
		}
		// Reject _observe in user-supplied YAML. This is an internal key
		// added by the composer for observe_alongside — if a user sets it
		// directly, they can silently downgrade any contract to observe mode.
		if _, has := cm["_observe"]; has {
			return fmt.Errorf("yaml: contract %q uses reserved internal key '_observe'", cm["id"])
		}
	}
	return nil
}

func schemaErrors(errs []gojsonschema.ResultError) string {
	if len(errs) == 0 {
		return "unknown schema error"
	}
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, err.String())
	}
	return strings.Join(msgs, "; ")
}

func validateUniqueIDs(data map[string]any) error {
	seen := make(map[string]bool)
	contracts, _ := data["contracts"].([]any)
	for _, c := range contracts {
		cm, _ := c.(map[string]any)
		id, _ := cm["id"].(string)
		if seen[id] {
			return fmt.Errorf("yaml: duplicate contract id: %q", id)
		}
		seen[id] = true
	}
	return nil
}

func validateRegexes(data map[string]any) error {
	contracts, _ := data["contracts"].([]any)
	for _, c := range contracts {
		cm, _ := c.(map[string]any)
		when, ok := cm["when"]
		if !ok {
			continue
		}
		if err := validateExprRegexes(when); err != nil {
			return err
		}
	}
	return nil
}

func validateExprRegexes(expr any) error {
	m, ok := expr.(map[string]any)
	if !ok {
		return nil
	}
	// Boolean combinators
	if subs, ok := m["all"].([]any); ok {
		for _, sub := range subs {
			if err := validateExprRegexes(sub); err != nil {
				return err
			}
		}
		return nil
	}
	if subs, ok := m["any"].([]any); ok {
		for _, sub := range subs {
			if err := validateExprRegexes(sub); err != nil {
				return err
			}
		}
		return nil
	}
	if not, ok := m["not"]; ok {
		return validateExprRegexes(not)
	}
	// Leaf node: selector -> {operator: value}
	for _, ops := range m {
		opsMap, ok := ops.(map[string]any)
		if !ok {
			continue
		}
		if pat, ok := opsMap["matches"].(string); ok {
			if _, err := regexp.Compile(pat); err != nil {
				return fmt.Errorf("yaml: invalid regex pattern %q: %w", pat, err)
			}
		}
		if pats, ok := opsMap["matches_any"].([]any); ok {
			for _, p := range pats {
				pat, _ := p.(string)
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf("yaml: invalid regex pattern %q: %w", pat, err)
				}
			}
		}
	}
	return nil
}

func validatePreSelectors(data map[string]any) error {
	contracts, _ := data["contracts"].([]any)
	for _, c := range contracts {
		cm, _ := c.(map[string]any)
		if cm["type"] != "pre" {
			continue
		}
		when, ok := cm["when"]
		if !ok {
			continue
		}
		if exprHasSelector(when, "output.text") {
			return fmt.Errorf("yaml: contract %q: output.text selector is not available in type: pre contracts", cm["id"])
		}
	}
	return nil
}

func exprHasSelector(expr any, target string) bool {
	m, ok := expr.(map[string]any)
	if !ok {
		return false
	}
	if subs, ok := m["all"].([]any); ok {
		for _, sub := range subs {
			if exprHasSelector(sub, target) {
				return true
			}
		}
		return false
	}
	if subs, ok := m["any"].([]any); ok {
		for _, sub := range subs {
			if exprHasSelector(sub, target) {
				return true
			}
		}
		return false
	}
	if not, ok := m["not"]; ok {
		return exprHasSelector(not, target)
	}
	_, found := m[target]
	return found
}
