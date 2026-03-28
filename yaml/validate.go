package yaml

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	metadataNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	ruleIDRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

var (
	topLevelKeys = map[string]bool{
		"apiVersion":        true,
		"kind":              true,
		"metadata":          true,
		"defaults":          true,
		"rules":             true,
		"tools":             true,
		"observability":     true,
		"observe_alongside": true,
	}
	preContractKeys = map[string]bool{
		"id": true, "type": true, "enabled": true, "mode": true,
		"tool": true, "when": true, "then": true,
	}
	postContractKeys = map[string]bool{
		"id": true, "type": true, "enabled": true, "mode": true,
		"tool": true, "when": true, "then": true,
	}
	sessionContractKeys = map[string]bool{
		"id": true, "type": true, "enabled": true, "mode": true,
		"limits": true, "then": true,
	}
	sandboxContractKeys = map[string]bool{
		"id": true, "type": true, "enabled": true, "mode": true,
		"tool": true, "tools": true, "within": true, "not_within": true,
		"allows": true, "not_allows": true, "outside": true, "message": true,
		"timeout": true, "timeout_action": true,
	}
)

// validateSchema applies handwritten structural validation matching the
// canonical Python YAML schema plus Go-specific reserved-key checks.
func validateSchema(data map[string]any) error {
	if err := validateAdditionalProperties(data, "", topLevelKeys); err != nil {
		return err
	}

	if apiVersion, ok := data["apiVersion"].(string); !ok || apiVersion == "" {
		return schemaError("apiVersion is required")
	} else if apiVersion != "edictum/v2" {
		return schemaError("apiVersion must be %q", "edictum/v2")
	}

	if kind, ok := data["kind"].(string); !ok || kind == "" {
		return schemaError("kind is required")
	} else if kind != "Ruleset" {
		return schemaError("kind must be %q", "Ruleset")
	}

	if err := validateMetadata(data["metadata"]); err != nil {
		return err
	}
	if err := validateDefaults(data["defaults"]); err != nil {
		return err
	}
	if err := validateObserveAlongside(data["observe_alongside"]); err != nil {
		return err
	}
	if err := validateTools(data["tools"]); err != nil {
		return err
	}
	if err := validateObservability(data["observability"]); err != nil {
		return err
	}
	if err := validateContracts(data["rules"]); err != nil {
		return err
	}

	return nil
}

func schemaError(format string, args ...any) error {
	return fmt.Errorf("yaml: schema validation failed: "+format, args...)
}

func validateAdditionalProperties(m map[string]any, path string, allowed map[string]bool) error {
	for key := range m {
		if !allowed[key] {
			if path == "" {
				return schemaError("additionalProperties %q not allowed", key)
			}
			return schemaError("%s.%s is not allowed", path, key)
		}
	}
	return nil
}

func validateMetadata(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return schemaError("metadata is required and must be an object")
	}
	if err := validateAdditionalProperties(m, "metadata", map[string]bool{
		"name": true, "description": true,
	}); err != nil {
		return err
	}

	name, ok := m["name"].(string)
	if !ok || name == "" {
		return schemaError("metadata.name is required")
	}
	if !metadataNameRe.MatchString(name) {
		return schemaError("metadata.name must match %q", metadataNameRe.String())
	}
	if desc, ok := m["description"]; ok {
		if _, ok := desc.(string); !ok {
			return schemaError("metadata.description must be a string")
		}
	}
	return nil
}

func validateDefaults(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return schemaError("defaults is required and must be an object")
	}
	if err := validateAdditionalProperties(m, "defaults", map[string]bool{"mode": true}); err != nil {
		return err
	}
	mode, ok := m["mode"].(string)
	if !ok || mode == "" {
		return schemaError("defaults.mode is required")
	}
	if mode != "enforce" && mode != "observe" {
		return schemaError("defaults.mode must be one of %q or %q", "enforce", "observe")
	}
	return nil
}

func validateObserveAlongside(v any) error {
	if v == nil {
		return nil
	}
	if _, ok := v.(bool); !ok {
		return schemaError("observe_alongside must be a boolean")
	}
	return nil
}

func validateTools(v any) error {
	if v == nil {
		return nil
	}
	tools, ok := v.(map[string]any)
	if !ok {
		return schemaError("tools must be an object")
	}
	for name, raw := range tools {
		td, ok := raw.(map[string]any)
		if !ok {
			return schemaError("tools.%s must be an object", name)
		}
		if err := validateAdditionalProperties(td, "tools."+name, map[string]bool{
			"side_effect": true,
			"idempotent":  true,
		}); err != nil {
			return err
		}
		sideEffect, ok := td["side_effect"].(string)
		if !ok || sideEffect == "" {
			return schemaError("tools.%s.side_effect is required", name)
		}
		switch sideEffect {
		case "pure", "read", "write", "irreversible":
		default:
			return schemaError("tools.%s.side_effect must be one of pure, read, write, irreversible", name)
		}
		if idempotent, ok := td["idempotent"]; ok {
			if _, ok := idempotent.(bool); !ok {
				return schemaError("tools.%s.idempotent must be a boolean", name)
			}
		}
	}
	return nil
}

func validateObservability(v any) error {
	if v == nil {
		return nil
	}
	obs, ok := v.(map[string]any)
	if !ok {
		return schemaError("observability must be an object")
	}
	if err := validateAdditionalProperties(obs, "observability", map[string]bool{
		"otel": true, "stdout": true, "file": true,
	}); err != nil {
		return err
	}
	if stdout, ok := obs["stdout"]; ok {
		if _, ok := stdout.(bool); !ok {
			return schemaError("observability.stdout must be a boolean")
		}
	}
	if file, ok := obs["file"]; ok {
		if file != nil {
			if _, ok := file.(string); !ok {
				return schemaError("observability.file must be a string or null")
			}
		}
	}
	if otel, ok := obs["otel"]; ok {
		otelMap, ok := otel.(map[string]any)
		if !ok {
			return schemaError("observability.otel must be an object")
		}
		if err := validateAdditionalProperties(otelMap, "observability.otel", map[string]bool{
			"enabled": true, "endpoint": true, "protocol": true, "service_name": true,
			"insecure": true, "resource_attributes": true,
		}); err != nil {
			return err
		}
		if enabled, ok := otelMap["enabled"]; ok {
			if _, ok := enabled.(bool); !ok {
				return schemaError("observability.otel.enabled must be a boolean")
			}
		}
		if endpoint, ok := otelMap["endpoint"]; ok {
			if _, ok := endpoint.(string); !ok {
				return schemaError("observability.otel.endpoint must be a string")
			}
		}
		if protocol, ok := otelMap["protocol"].(string); ok {
			if protocol != "grpc" && protocol != "http" {
				return schemaError("observability.otel.protocol must be one of %q or %q", "grpc", "http")
			}
		} else if _, ok := otelMap["protocol"]; ok {
			return schemaError("observability.otel.protocol must be a string")
		}
		if serviceName, ok := otelMap["service_name"]; ok {
			if _, ok := serviceName.(string); !ok {
				return schemaError("observability.otel.service_name must be a string")
			}
		}
		if insecure, ok := otelMap["insecure"]; ok {
			if _, ok := insecure.(bool); !ok {
				return schemaError("observability.otel.insecure must be a boolean")
			}
		}
		if attrs, ok := otelMap["resource_attributes"]; ok {
			attrMap, ok := attrs.(map[string]any)
			if !ok {
				return schemaError("observability.otel.resource_attributes must be an object")
			}
			for key, value := range attrMap {
				if _, ok := value.(string); !ok {
					return schemaError("observability.otel.resource_attributes.%s must be a string", key)
				}
			}
		}
	}
	return nil
}

func validateContracts(v any) error {
	rules, ok := v.([]any)
	if !ok {
		return schemaError("rules is required and must be an array")
	}
	if len(rules) == 0 {
		return schemaError("rules must contain at least 1 item")
	}
	for i, raw := range rules {
		contractMap, ok := raw.(map[string]any)
		if !ok {
			return schemaError("rules[%d] must be an object", i)
		}
		if err := validateContract(contractMap, i); err != nil {
			return err
		}
	}
	return nil
}

func validateContract(contractMap map[string]any, index int) error {
	if _, has := contractMap["_observe"]; has {
		return fmt.Errorf("yaml: rule %q uses reserved internal key '_observe'", contractMap["id"])
	}

	ruleID, ok := contractMap["id"].(string)
	if !ok || ruleID == "" {
		return schemaError("rules[%d].id is required", index)
	}
	if !ruleIDRe.MatchString(ruleID) {
		return schemaError("rules[%d].id must match %q", index, ruleIDRe.String())
	}

	contractType, ok := contractMap["type"].(string)
	if !ok || contractType == "" {
		return schemaError("rules[%d].type is required", index)
	}

	switch contractType {
	case "pre":
		if err := validateAdditionalProperties(contractMap, contractPath(index), preContractKeys); err != nil {
			return err
		}
		if err := validateCommonContractFields(contractMap, index, true); err != nil {
			return err
		}
		if err := validateExpressionField(contractMap["when"], contractPath(index)+".when"); err != nil {
			return err
		}
		return validateThenMap(contractMap["then"], contractPath(index)+".then", "pre")
	case "post":
		if err := validateAdditionalProperties(contractMap, contractPath(index), postContractKeys); err != nil {
			return err
		}
		if err := validateCommonContractFields(contractMap, index, true); err != nil {
			return err
		}
		if err := validateExpressionField(contractMap["when"], contractPath(index)+".when"); err != nil {
			return err
		}
		return validateThenMap(contractMap["then"], contractPath(index)+".then", "post")
	case "session":
		if err := validateAdditionalProperties(contractMap, contractPath(index), sessionContractKeys); err != nil {
			return err
		}
		if err := validateCommonContractFields(contractMap, index, false); err != nil {
			return err
		}
		if err := validateSessionLimits(contractMap["limits"], contractPath(index)+".limits"); err != nil {
			return err
		}
		return validateThenMap(contractMap["then"], contractPath(index)+".then", "session")
	case "sandbox":
		if err := validateAdditionalProperties(contractMap, contractPath(index), sandboxContractKeys); err != nil {
			return err
		}
		if err := validateCommonContractFields(contractMap, index, false); err != nil {
			return err
		}
		if err := validateSandboxStructural(contractMap, index); err != nil {
			return err
		}
		return nil
	default:
		return schemaError("rules[%d].type must be one of pre, post, session, sandbox", index)
	}
}

func contractPath(index int) string {
	return fmt.Sprintf("rules[%d]", index)
}

func validateCommonContractFields(contractMap map[string]any, index int, requireTool bool) error {
	if enabled, ok := contractMap["enabled"]; ok {
		if _, ok := enabled.(bool); !ok {
			return schemaError("rules[%d].enabled must be a boolean", index)
		}
	}
	if mode, ok := contractMap["mode"].(string); ok {
		if mode != "enforce" && mode != "observe" {
			return schemaError("rules[%d].mode must be one of %q or %q", index, "enforce", "observe")
		}
	} else if _, ok := contractMap["mode"]; ok {
		return schemaError("rules[%d].mode must be a string", index)
	}

	if requireTool {
		if err := validateToolSelector(contractMap["tool"], fmt.Sprintf("rules[%d].tool", index), true); err != nil {
			return err
		}
	}
	return nil
}

func validateToolSelector(v any, path string, required bool) error {
	if v == nil {
		if required {
			return schemaError("%s is required", path)
		}
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return schemaError("%s must be a string", path)
	}
	if strings.TrimSpace(s) == "" {
		return schemaError("%s must be non-empty", path)
	}
	return nil
}

func validateThenMap(v any, path, contractType string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return schemaError("%s is required and must be an object", path)
	}

	allowed := map[string]bool{
		"action": true, "message": true, "tags": true, "metadata": true,
	}
	if contractType == "pre" {
		allowed["timeout"] = true
		allowed["timeout_action"] = true
	}
	if err := validateAdditionalProperties(m, path, allowed); err != nil {
		return err
	}

	effect, ok := m["action"].(string)
	if !ok || effect == "" {
		return schemaError("%s.action is required", path)
	}
	switch contractType {
	case "pre":
		if effect != "block" && effect != "ask" {
			return schemaError("%s.action must be one of block or ask", path)
		}
	case "post":
		if effect != "warn" && effect != "redact" && effect != "block" {
			return schemaError("%s.action must be one of warn, redact, block", path)
		}
	case "session":
		if effect != "block" {
			return schemaError("%s.action must be %q", path, "block")
		}
	}

	if err := validateMessageString(m["message"], path+".message", true); err != nil {
		return err
	}
	if err := validateTags(m["tags"], path+".tags"); err != nil {
		return err
	}
	if metadata, ok := m["metadata"]; ok {
		if _, ok := metadata.(map[string]any); !ok {
			return schemaError("%s.metadata must be an object", path)
		}
	}
	if contractType == "pre" {
		if timeout, ok := m["timeout"]; ok {
			n, ok := intOrSchema(timeout)
			if !ok || n < 1 {
				return schemaError("%s.timeout must be an integer >= 1", path)
			}
		}
		if timeoutEffect, ok := m["timeout_action"].(string); ok {
			if timeoutEffect != "block" && timeoutEffect != "allow" {
				return schemaError("%s.timeout_action must be one of block or allow", path)
			}
		} else if _, ok := m["timeout_action"]; ok {
			return schemaError("%s.timeout_action must be a string", path)
		}
	}

	return nil
}

func validateMessageString(v any, path string, required bool) error {
	if v == nil {
		if required {
			return schemaError("%s is required", path)
		}
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return schemaError("%s must be a string", path)
	}
	if s == "" {
		return schemaError("%s must be non-empty", path)
	}
	if len(s) > 500 {
		return schemaError("%s must be at most 500 characters", path)
	}
	return nil
}

func validateTags(v any, path string) error {
	if v == nil {
		return nil
	}
	items, ok := v.([]any)
	if !ok {
		return schemaError("%s must be an array", path)
	}
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return schemaError("%s[%d] must be a string", path, i)
		}
		if s == "" {
			return schemaError("%s[%d] must be non-empty", path, i)
		}
	}
	return nil
}

func validateSessionLimits(v any, path string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return schemaError("%s is required and must be an object", path)
	}
	if err := validateAdditionalProperties(m, path, map[string]bool{
		"max_tool_calls": true, "max_attempts": true, "max_calls_per_tool": true,
	}); err != nil {
		return err
	}
	if len(m) == 0 {
		return schemaError("%s must define at least one limit", path)
	}
	if v, ok := m["max_tool_calls"]; ok {
		n, ok := intOrSchema(v)
		if !ok || n < 1 {
			return schemaError("%s.max_tool_calls must be an integer >= 1", path)
		}
	}
	if v, ok := m["max_attempts"]; ok {
		n, ok := intOrSchema(v)
		if !ok || n < 1 {
			return schemaError("%s.max_attempts must be an integer >= 1", path)
		}
	}
	if v, ok := m["max_calls_per_tool"]; ok {
		perTool, ok := v.(map[string]any)
		if !ok {
			return schemaError("%s.max_calls_per_tool must be an object", path)
		}
		if len(perTool) == 0 {
			return schemaError("%s.max_calls_per_tool must define at least one tool", path)
		}
		for tool, raw := range perTool {
			n, ok := intOrSchema(raw)
			if !ok || n < 1 {
				return schemaError("%s.max_calls_per_tool.%s must be an integer >= 1", path, tool)
			}
		}
	}
	return nil
}

func validateExpressionField(v any, path string) error {
	if v == nil {
		return schemaError("%s is required", path)
	}
	return validateExpression(v, path)
}

func validateExpression(expr any, path string) error {
	m, ok := expr.(map[string]any)
	if !ok {
		return schemaError("%s must be an object", path)
	}
	if len(m) == 0 {
		return schemaError("%s must be non-empty", path)
	}

	if raw, ok := m["all"]; ok {
		if len(m) != 1 {
			return schemaError("%s must only contain %q", path, "all")
		}
		items, ok := raw.([]any)
		if !ok {
			return schemaError("%s.all must be an array", path)
		}
		if len(items) == 0 {
			return schemaError("%s.all must contain at least 1 item", path)
		}
		for i, item := range items {
			if err := validateExpression(item, fmt.Sprintf("%s.all[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	}

	if raw, ok := m["any"]; ok {
		if len(m) != 1 {
			return schemaError("%s must only contain %q", path, "any")
		}
		items, ok := raw.([]any)
		if !ok {
			return schemaError("%s.any must be an array", path)
		}
		if len(items) == 0 {
			return schemaError("%s.any must contain at least 1 item", path)
		}
		for i, item := range items {
			if err := validateExpression(item, fmt.Sprintf("%s.any[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	}

	if raw, ok := m["not"]; ok {
		if len(m) != 1 {
			return schemaError("%s must only contain %q", path, "not")
		}
		return validateExpression(raw, path+".not")
	}

	if len(m) != 1 {
		return schemaError("%s leaf expressions must contain exactly one selector", path)
	}
	for selector, raw := range m {
		if selector == "all" || selector == "any" || selector == "not" {
			return schemaError("%s.%s is not allowed in a leaf expression", path, selector)
		}
		operatorMap, ok := raw.(map[string]any)
		if !ok {
			return schemaError("%s.%s must be an object", path, selector)
		}
		if len(operatorMap) != 1 {
			return schemaError("%s.%s must contain exactly one operator", path, selector)
		}
		for op, value := range operatorMap {
			if err := validateOperatorValue(op, value, path+"."+selector+"."+op); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOperatorValue(op string, value any, path string) error {
	switch op {
	case "exists":
		if _, ok := value.(bool); !ok {
			return schemaError("%s must be a boolean", path)
		}
	case "in", "not_in":
		items, ok := value.([]any)
		if !ok {
			return schemaError("%s must be an array", path)
		}
		if len(items) == 0 {
			return schemaError("%s must contain at least 1 item", path)
		}
	case "contains", "starts_with", "ends_with", "matches":
		if err := validateStringOperand(value, path, true); err != nil {
			return err
		}
	case "contains_any", "matches_any":
		items, ok := value.([]any)
		if !ok {
			return schemaError("%s must be an array", path)
		}
		if len(items) == 0 {
			return schemaError("%s must contain at least 1 item", path)
		}
		for i, item := range items {
			if err := validateStringOperand(item, fmt.Sprintf("%s[%d]", path, i), true); err != nil {
				return err
			}
		}
	case "gt", "gte", "lt", "lte":
		if _, ok := numberOperand(value); !ok {
			return schemaError("%s must be a number", path)
		}
	default:
		// Preserve Python behavior: unknown operators are allowed at load time
		// and rejected at compile time unless supplied as custom operators.
	}
	return nil
}

func validateStringOperand(v any, path string, nonEmpty bool) error {
	s, ok := v.(string)
	if !ok {
		return schemaError("%s must be a string", path)
	}
	if nonEmpty && s == "" {
		return schemaError("%s must be non-empty", path)
	}
	return nil
}

func numberOperand(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

func intOrSchema(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if float64(int(n)) != n {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func validateSandboxStructural(contractMap map[string]any, index int) error {
	hasTool := contractMap["tool"] != nil
	hasTools := contractMap["tools"] != nil
	if hasTool == hasTools {
		return schemaError("rules[%d] sandbox rules must set exactly one of tool or tools", index)
	}
	if hasTool {
		if err := validateToolSelector(contractMap["tool"], fmt.Sprintf("rules[%d].tool", index), true); err != nil {
			return err
		}
	}
	if hasTools {
		tools, ok := contractMap["tools"].([]any)
		if !ok {
			return schemaError("rules[%d].tools must be an array", index)
		}
		if len(tools) == 0 {
			return schemaError("rules[%d].tools must contain at least 1 item", index)
		}
		for i, raw := range tools {
			if err := validateToolSelector(raw, fmt.Sprintf("rules[%d].tools[%d]", index, i), true); err != nil {
				return err
			}
		}
	}
	if err := validateMessageString(contractMap["message"], fmt.Sprintf("rules[%d].message", index), true); err != nil {
		return err
	}
	if outside, ok := contractMap["outside"].(string); ok {
		if outside != "block" && outside != "ask" {
			return schemaError("rules[%d].outside must be one of block or ask", index)
		}
	} else if _, ok := contractMap["outside"]; ok {
		return schemaError("rules[%d].outside must be a string", index)
	}
	if timeout, ok := contractMap["timeout"]; ok {
		n, ok := intOrSchema(timeout)
		if !ok || n < 1 {
			return schemaError("rules[%d].timeout must be an integer >= 1", index)
		}
	}
	if timeoutEffect, ok := contractMap["timeout_action"].(string); ok {
		if timeoutEffect != "block" && timeoutEffect != "allow" {
			return schemaError("rules[%d].timeout_action must be one of block or allow", index)
		}
	} else if _, ok := contractMap["timeout_action"]; ok {
		return schemaError("rules[%d].timeout_action must be a string", index)
	}
	if within, ok := contractMap["within"]; ok {
		items, ok := within.([]any)
		if !ok {
			return schemaError("rules[%d].within must be an array", index)
		}
		if len(items) == 0 {
			return schemaError("rules[%d].within must contain at least 1 item", index)
		}
		if err := validateStringArray(items, fmt.Sprintf("rules[%d].within", index)); err != nil {
			return err
		}
	}
	if notWithin, ok := contractMap["not_within"]; ok {
		items, ok := notWithin.([]any)
		if !ok {
			return schemaError("rules[%d].not_within must be an array", index)
		}
		if err := validateStringArray(items, fmt.Sprintf("rules[%d].not_within", index)); err != nil {
			return err
		}
	}
	if err := validateSandboxAllows(contractMap["allows"], fmt.Sprintf("rules[%d].allows", index)); err != nil {
		return err
	}
	if err := validateSandboxNotAllows(contractMap["not_allows"], fmt.Sprintf("rules[%d].not_allows", index)); err != nil {
		return err
	}
	if contractMap["within"] == nil && contractMap["allows"] == nil {
		return schemaError("rules[%d] sandbox rules must set at least one of within or allows", index)
	}
	return nil
}

func validateSandboxAllows(v any, path string) error {
	if v == nil {
		return nil
	}
	allows, ok := v.(map[string]any)
	if !ok {
		return schemaError("%s must be an object", path)
	}
	if err := validateAdditionalProperties(allows, path, map[string]bool{
		"commands": true, "domains": true,
	}); err != nil {
		return err
	}
	if commands, ok := allows["commands"]; ok {
		items, ok := commands.([]any)
		if !ok {
			return schemaError("%s.commands must be an array", path)
		}
		if len(items) == 0 {
			return schemaError("%s.commands must contain at least 1 item", path)
		}
		for i, item := range items {
			if err := validateStringOperand(item, fmt.Sprintf("%s.commands.%d", path, i), true); err != nil {
				return err
			}
		}
	}
	if domains, ok := allows["domains"]; ok {
		items, ok := domains.([]any)
		if !ok {
			return schemaError("%s.domains must be an array", path)
		}
		if len(items) == 0 {
			return schemaError("%s.domains must contain at least 1 item", path)
		}
		for i, item := range items {
			if err := validateStringOperand(item, fmt.Sprintf("%s.domains.%d", path, i), true); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSandboxNotAllows(v any, path string) error {
	if v == nil {
		return nil
	}
	notAllows, ok := v.(map[string]any)
	if !ok {
		return schemaError("%s must be an object", path)
	}
	if err := validateAdditionalProperties(notAllows, path, map[string]bool{"domains": true}); err != nil {
		return err
	}
	if domains, ok := notAllows["domains"]; ok {
		items, ok := domains.([]any)
		if !ok {
			return schemaError("%s.domains must be an array", path)
		}
		if len(items) == 0 {
			return schemaError("%s.domains must contain at least 1 item", path)
		}
		for i, item := range items {
			if err := validateStringOperand(item, fmt.Sprintf("%s.domains.%d", path, i), true); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStringArray(items []any, path string) error {
	for i, item := range items {
		if err := validateStringOperand(item, fmt.Sprintf("%s.%d", path, i), true); err != nil {
			return err
		}
	}
	return nil
}

func validateUniqueIDs(data map[string]any) error {
	seen := make(map[string]bool)
	rules, _ := data["rules"].([]any)
	for _, c := range rules {
		cm, _ := c.(map[string]any)
		id, _ := cm["id"].(string)
		if seen[id] {
			return fmt.Errorf("yaml: duplicate rule id: %q", id)
		}
		seen[id] = true
	}
	return nil
}

func validateRegexes(data map[string]any) error {
	rules, _ := data["rules"].([]any)
	for _, c := range rules {
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
	rules, _ := data["rules"].([]any)
	for _, c := range rules {
		cm, _ := c.(map[string]any)
		if cm["type"] != "pre" {
			continue
		}
		when, ok := cm["when"]
		if !ok {
			continue
		}
		if exprHasSelector(when, "output.text") {
			return fmt.Errorf("yaml: rule %q: output.text selector is not available in type: pre rules", cm["id"])
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
