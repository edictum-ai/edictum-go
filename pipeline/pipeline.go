// Package pipeline implements the 5-stage governance pipeline.
package pipeline

// PreDecision is the result of pre-execution governance checks.
type PreDecision struct {
	Action               string // "allow", "deny", "pending_approval"
	Reason               string
	DecisionSource       string
	DecisionName         string
	HooksEvaluated       int
	ContractsEvaluated   int
	Observed             bool
	PolicyError          bool
	ObserveResults       []ObserveResult
	ApprovalTimeout      *int
	ApprovalTimeoutEff   string
	ApprovalMessage      string
}

// PostDecision is the result of post-execution governance checks.
type PostDecision struct {
	ToolSuccess          bool
	PostconditionsPassed bool
	Warnings             []string
	ContractsEvaluated   int
	PolicyError          bool
	RedactedResponse     any
	OutputSuppressed     bool
}

// ObserveResult captures the result of an observe-mode contract evaluation.
type ObserveResult struct {
	ContractName string
	Passed       bool
	Message      string
}

// GovernancePipeline orchestrates the 5-stage governance flow.
type GovernancePipeline struct {
	// Implementation will be filled during Phase 1
}
