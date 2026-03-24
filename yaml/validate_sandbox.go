package yaml

import "fmt"

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
		if nw, ok := cm["not_within"].([]any); ok && len(nw) > 0 {
			if _, ok := cm["within"]; !ok {
				return fmt.Errorf("yaml: contract %q: not_within requires within to also be set", cid)
			}
			if err := validateStringList(cid, "not_within", nw); err != nil {
				return err
			}
		} else if _, ok := cm["not_within"]; ok {
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
			if doms, ok := na["domains"].([]any); ok && len(doms) > 0 {
				if err := validateStringList(cid, "not_allows.domains", doms); err != nil {
					return err
				}
				allows, _ := cm["allows"].(map[string]any)
				if _, ok := allows["domains"]; !ok {
					return fmt.Errorf("yaml: contract %q: not_allows.domains requires allows.domains to also be set", cid)
				}
			} else if _, ok := na["domains"]; ok {
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
