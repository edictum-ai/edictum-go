package pipeline

import (
	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

// ContractProvider is the interface the pipeline uses to access
// contracts, hooks, and limits from the guard. The guard package
// implements this interface.
type ContractProvider interface {
	GetLimits() OperationLimits
	GetHooks(phase string, env envelope.ToolEnvelope) []HookRegistration
	GetPreconditions(env envelope.ToolEnvelope) []contract.Precondition
	GetPostconditions(env envelope.ToolEnvelope) []contract.Postcondition
	GetObservePostconditions(env envelope.ToolEnvelope) []contract.Postcondition
	GetSandboxContracts(env envelope.ToolEnvelope) []contract.Precondition
	GetSessionContracts() []contract.SessionContract
	GetObservePreconditions(env envelope.ToolEnvelope) []contract.Precondition
	GetObserveSandboxContracts(env envelope.ToolEnvelope) []contract.Precondition
	GetObserveSessionContracts() []contract.SessionContract
}
