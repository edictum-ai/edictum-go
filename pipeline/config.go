package pipeline

import (
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/workflow"
)

// RuleProvider is the interface the pipeline uses to access
// rules, hooks, and limits from the guard. The guard package
// implements this interface.
type RuleProvider interface {
	GetLimits() OperationLimits
	GetHooks(phase string, env toolcall.ToolCall) []HookRegistration
	GetPreconditions(env toolcall.ToolCall) []rule.Precondition
	GetPostconditions(env toolcall.ToolCall) []rule.Postcondition
	GetObservePostconditions(env toolcall.ToolCall) []rule.Postcondition
	GetSandboxRules(env toolcall.ToolCall) []rule.Precondition
	GetSessionRules() []rule.SessionRule
	GetObservePreconditions(env toolcall.ToolCall) []rule.Precondition
	GetObserveSandboxRules(env toolcall.ToolCall) []rule.Precondition
	GetObserveSessionRules() []rule.SessionRule
	GetWorkflowRuntime() *workflow.Runtime
}
