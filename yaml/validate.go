package yaml

import (
	"fmt"
	"regexp"
)

// validateSchema checks required top-level fields and basic contract structure.
// Full JSON Schema validation is deferred until the jsonschema library is integrated.
func validateSchema(data map[string]any) error {
	if v, _ := data["apiVersion"].(string); v != "edictum/v1" {
		return fmt.Errorf("yaml: apiVersion must be 'edictum/v1', got %q", data["apiVersion"])
	}
	if v, _ := data["kind"].(string); v != "ContractBundle" {
		return fmt.Errorf("yaml: kind must be 'ContractBundle', got %q", data["kind"])
	}
	if defaults, ok := data["defaults"].(map[string]any); ok {
		if mode, exists := defaults["mode"]; exists {
			m, _ := mode.(string)
			if m != "enforce" && m != "observe" {
				return fmt.Errorf("yaml: defaults.mode must be 'enforce' or 'observe', got %q", mode)
			}
		}
	}
	contracts, _ := data["contracts"].([]any)
	for i, c := range contracts {
		cm, ok := c.(map[string]any)
		if !ok {
			return fmt.Errorf("yaml: contract at index %d must be a mapping", i)
		}
		if _, ok := cm["id"].(string); !ok {
			return fmt.Errorf("yaml: contract at index %d missing required field 'id'", i)
		}
		ctype, _ := cm["type"].(string)
		switch ctype {
		case "pre", "post", "session", "sandbox":
			// valid
		default:
			return fmt.Errorf("yaml: contract %q has invalid type %q", cm["id"], ctype)
		}
		if ctype != "session" {
			if _, ok := cm["tool"].(string); !ok {
				return fmt.Errorf("yaml: contract %q of type %q missing required field 'tool'", cm["id"], ctype)
			}
		}
		// Validate per-contract mode if present.
		if modeVal, exists := cm["mode"]; exists {
			modeStr, _ := modeVal.(string)
			if modeStr != "enforce" && modeStr != "observe" {
				return fmt.Errorf("yaml: contract %q has invalid mode %q (must be 'enforce' or 'observe')", cm["id"], modeVal)
			}
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

func validateSandboxContracts(data map[string]any) error {
	contracts, _ := data["contracts"].([]any)
	for _, c := range contracts {
		cm, _ := c.(map[string]any)
		if cm["type"] != "sandbox" {
			continue
		}
		cid, _ := cm["id"].(string)
		// Require at least one non-empty primary constraint — a sandbox
		// contract with no effective boundaries would silently allow all calls.
		// Empty lists (within: []) and empty maps (allows: {}) do not count.
		// All list entries must be strings — non-strings would be silently
		// dropped during compilation, potentially disabling enforcement.
		hasConstraint := false
		if within, ok := cm["within"].([]any); ok && len(within) > 0 {
			if err := validateStringList(cid, "within", within); err != nil {
				return err
			}
			hasConstraint = true
		}
		if allows, ok := cm["allows"].(map[string]any); ok {
			if cmds, ok := allows["commands"].([]any); ok && len(cmds) > 0 {
				if err := validateStringList(cid, "allows.commands", cmds); err != nil {
					return err
				}
				hasConstraint = true
			}
			if doms, ok := allows["domains"].([]any); ok && len(doms) > 0 {
				if err := validateStringList(cid, "allows.domains", doms); err != nil {
					return err
				}
				hasConstraint = true
			}
		}
		if !hasConstraint {
			return fmt.Errorf("yaml: contract %q: sandbox contract must have at least one primary constraint (within or allows with non-empty values)", cid)
		}
		if _, ok := cm["not_within"]; ok {
			if _, ok := cm["within"]; !ok {
				return fmt.Errorf("yaml: contract %q: not_within requires within to also be set", cid)
			}
		}
		if _, ok := cm["not_allows"]; ok {
			if _, ok := cm["allows"]; !ok {
				return fmt.Errorf("yaml: contract %q: not_allows requires allows to also be set", cid)
			}
		}
		if na, ok := cm["not_allows"].(map[string]any); ok {
			// Only "domains" is a valid key in not_allows.
			for key := range na {
				if key != "domains" {
					return fmt.Errorf("yaml: contract %q: not_allows.%s is not supported (only not_allows.domains is valid)", cid, key)
				}
			}
			if _, ok := na["domains"]; ok {
				allows, _ := cm["allows"].(map[string]any)
				if _, ok := allows["domains"]; !ok {
					return fmt.Errorf("yaml: contract %q: not_allows.domains requires allows.domains to also be set", cid)
				}
			}
		}
	}
	return nil
}

// validateStringList checks that all entries in a YAML list are strings.
// Non-string entries would be silently dropped during compilation,
// potentially disabling enforcement on security-critical boundaries.
func validateStringList(cid, field string, items []any) error {
	for i, entry := range items {
		if _, ok := entry.(string); !ok {
			return fmt.Errorf("yaml: contract %q: %s[%d] must be a string, got %T", cid, field, i, entry)
		}
	}
	return nil
}
