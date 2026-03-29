package guard

import (
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/workflow"
)

// Compile-time check that Guard implements RuleProvider.
var _ pipeline.RuleProvider = (*Guard)(nil)

// GetLimits returns the current operation limits.
func (g *Guard) GetLimits() pipeline.OperationLimits {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.state.limits
}

// GetHooks returns hooks matching the given phase and ToolCall.
func (g *Guard) GetHooks(phase string, env toolcall.ToolCall) []pipeline.HookRegistration {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if phase == "before" {
		return filterHooks(g.beforeHooks, env)
	}
	return filterHooks(g.afterHooks, env)
}

// GetPreconditions returns enforce-mode preconditions matching the tool.
func (g *Guard) GetPreconditions(env toolcall.ToolCall) []rule.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPreconditions(g.state.preconditions, env)
}

// GetPostconditions returns enforce-mode postconditions matching the tool.
func (g *Guard) GetPostconditions(env toolcall.ToolCall) []rule.Postcondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPostconditions(g.state.postconditions, env)
}

// GetSandboxRules returns enforce-mode sandbox rules matching the tool.
func (g *Guard) GetSandboxRules(env toolcall.ToolCall) []rule.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterSandbox(g.state.sandboxRules, env)
}

// GetSessionRules returns all enforce-mode session rules.
func (g *Guard) GetSessionRules() []rule.SessionRule {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]rule.SessionRule, len(g.state.sessionRules))
	copy(result, g.state.sessionRules)
	return result
}

// GetObservePreconditions returns observe-mode preconditions matching the tool.
func (g *Guard) GetObservePreconditions(env toolcall.ToolCall) []rule.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPreconditions(g.state.observePreconditions, env)
}

// GetObservePostconditions returns observe-mode postconditions matching the tool.
func (g *Guard) GetObservePostconditions(env toolcall.ToolCall) []rule.Postcondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPostconditions(g.state.observePostconditions, env)
}

// GetObserveSandboxRules returns observe-mode sandbox rules matching the tool.
func (g *Guard) GetObserveSandboxRules(env toolcall.ToolCall) []rule.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterSandbox(g.state.observeSandboxRules, env)
}

// GetObserveSessionRules returns all observe-mode session rules.
func (g *Guard) GetObserveSessionRules() []rule.SessionRule {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]rule.SessionRule, len(g.state.observeSessionRules))
	copy(result, g.state.observeSessionRules)
	return result
}

// GetWorkflowRuntime returns the configured workflow runtime, if any.
func (g *Guard) GetWorkflowRuntime() *workflow.Runtime {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.workflowRuntime
}
