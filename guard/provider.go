package guard

import (
	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
)

// Compile-time check that Guard implements ContractProvider.
var _ pipeline.ContractProvider = (*Guard)(nil)

// GetLimits returns the current operation limits.
func (g *Guard) GetLimits() pipeline.OperationLimits {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.state.limits
}

// GetHooks returns hooks matching the given phase and tool envelope.
func (g *Guard) GetHooks(phase string, env envelope.ToolEnvelope) []pipeline.HookRegistration {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if phase == "before" {
		return filterHooks(g.beforeHooks, env)
	}
	return filterHooks(g.afterHooks, env)
}

// GetPreconditions returns enforce-mode preconditions matching the tool.
func (g *Guard) GetPreconditions(env envelope.ToolEnvelope) []contract.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPreconditions(g.state.preconditions, env)
}

// GetPostconditions returns enforce-mode postconditions matching the tool.
func (g *Guard) GetPostconditions(env envelope.ToolEnvelope) []contract.Postcondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPostconditions(g.state.postconditions, env)
}

// GetSandboxContracts returns enforce-mode sandbox contracts matching the tool.
func (g *Guard) GetSandboxContracts(env envelope.ToolEnvelope) []contract.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterSandbox(g.state.sandboxContracts, env)
}

// GetSessionContracts returns all enforce-mode session contracts.
func (g *Guard) GetSessionContracts() []contract.SessionContract {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]contract.SessionContract, len(g.state.sessionContracts))
	copy(result, g.state.sessionContracts)
	return result
}

// GetObservePreconditions returns observe-mode preconditions matching the tool.
func (g *Guard) GetObservePreconditions(env envelope.ToolEnvelope) []contract.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPreconditions(g.state.observePreconditions, env)
}

// GetObservePostconditions returns observe-mode postconditions matching the tool.
func (g *Guard) GetObservePostconditions(env envelope.ToolEnvelope) []contract.Postcondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterPostconditions(g.state.observePostconditions, env)
}

// GetObserveSandboxContracts returns observe-mode sandbox contracts matching the tool.
func (g *Guard) GetObserveSandboxContracts(env envelope.ToolEnvelope) []contract.Precondition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterSandbox(g.state.observeSandboxContracts, env)
}

// GetObserveSessionContracts returns all observe-mode session contracts.
func (g *Guard) GetObserveSessionContracts() []contract.SessionContract {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]contract.SessionContract, len(g.state.observeSessionContracts))
	copy(result, g.state.observeSessionContracts)
	return result
}
