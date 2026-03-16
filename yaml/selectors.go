package yaml

import (
	"os"
	"strconv"
	"strings"

	"github.com/edictum-ai/edictum-go/envelope"
)

// missing is the sentinel for "field not found".
var missing = &struct{}{}

// resolveSelector resolves a dotted selector path to a value from the envelope.
// Returns missing if the field is not found at any level.
func resolveSelector(selector string, env envelope.ToolEnvelope, outputText string, ec *evalCtx) any {
	if selector == "environment" {
		return env.Environment()
	}

	if selector == "tool.name" {
		return env.ToolName()
	}

	if strings.HasPrefix(selector, "args.") {
		return resolveNested(selector[5:], env.Args())
	}

	if strings.HasPrefix(selector, "principal.") {
		p := env.Principal()
		if p == nil {
			return missing
		}
		rest := selector[10:]
		switch rest {
		case "user_id":
			return p.UserID()
		case "service_id":
			return p.ServiceID()
		case "org_id":
			return p.OrgID()
		case "role":
			return p.Role()
		case "ticket_ref":
			return p.TicketRef()
		}
		if strings.HasPrefix(rest, "claims.") {
			return resolveNested(rest[7:], p.Claims())
		}
		return missing
	}

	if selector == "output.text" {
		if outputText == "" {
			return missing
		}
		return outputText
	}

	if strings.HasPrefix(selector, "env.") {
		varName := selector[4:]
		raw, ok := os.LookupEnv(varName)
		if !ok {
			return missing
		}
		return coerceEnvValue(raw)
	}

	if strings.HasPrefix(selector, "metadata.") {
		return resolveNested(selector[9:], env.Metadata())
	}

	// Custom selectors: match prefix before first dot.
	if ec != nil && ec.customSelectors != nil {
		dotPos := strings.IndexByte(selector, '.')
		if dotPos > 0 {
			prefix := selector[:dotPos]
			if resolver, ok := ec.customSelectors[prefix]; ok {
				data := resolver(env)
				rest := selector[dotPos+1:]
				return resolveNested(rest, data)
			}
		}
	}

	return missing
}

// resolveNested resolves a dotted path through nested maps.
// Returns missing if any intermediate key is absent or data is not a map.
func resolveNested(path string, data any) any {
	if data == nil {
		return missing
	}
	parts := strings.Split(path, ".")
	current := data
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return missing
		}
		v, exists := m[part]
		if !exists {
			return missing
		}
		current = v
	}
	return current
}

// coerceEnvValue coerces an environment variable string to a typed value.
func coerceEnvValue(raw string) any {
	low := strings.ToLower(raw)
	if low == "true" {
		return true
	}
	if low == "false" {
		return false
	}
	if i, err := strconv.Atoi(raw); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f
	}
	return raw
}
