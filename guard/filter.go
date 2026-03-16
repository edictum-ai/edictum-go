package guard

import (
	"path"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
)

// filterPreconditions returns preconditions matching the tool name.
// Uses path.Match for glob matching (e.g. "Bash*", "Read").
func filterPreconditions(pres []contract.Precondition, env envelope.ToolEnvelope) []contract.Precondition {
	var result []contract.Precondition
	for _, p := range pres {
		if !toolMatches(p.Tool, env.ToolName()) {
			continue
		}
		result = append(result, p)
	}
	return result
}

// filterPostconditions returns postconditions matching the tool name.
func filterPostconditions(posts []contract.Postcondition, env envelope.ToolEnvelope) []contract.Postcondition {
	var result []contract.Postcondition
	for _, p := range posts {
		if !toolMatches(p.Tool, env.ToolName()) {
			continue
		}
		result = append(result, p)
	}
	return result
}

// filterSandbox returns sandbox contracts matching the tool name.
// Sandbox contracts use the Tool field as a glob pattern.
func filterSandbox(contracts []contract.Precondition, env envelope.ToolEnvelope) []contract.Precondition {
	var result []contract.Precondition
	for _, c := range contracts {
		if !toolMatches(c.Tool, env.ToolName()) {
			continue
		}
		result = append(result, c)
	}
	return result
}

// filterHooks returns hooks matching the phase and tool name.
func filterHooks(hooks []pipeline.HookRegistration, env envelope.ToolEnvelope) []pipeline.HookRegistration {
	var result []pipeline.HookRegistration
	for _, h := range hooks {
		if !toolMatches(h.Tool, env.ToolName()) {
			continue
		}
		result = append(result, h)
	}
	return result
}

// toolMatches checks if a tool pattern matches a tool name.
// "*" matches all tools. Otherwise uses path.Match for glob matching.
func toolMatches(pattern, toolName string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, toolName)
	if err != nil {
		// Invalid pattern: fail closed (no match).
		return false
	}
	return matched
}
