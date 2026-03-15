package pipeline

// PreDecision is the result of pre-execution governance checks.
type PreDecision struct {
	Action             string
	Reason             string
	DecisionSource     string
	DecisionName       string
	HooksEvaluated     []map[string]any
	ContractsEvaluated []map[string]any
	Observed           bool
	PolicyError        bool
	ObserveResults     []map[string]any
	ApprovalTimeout    int
	ApprovalTimeoutEff string
	ApprovalMessage    string
}

// PostDecision is the result of post-execution governance checks.
type PostDecision struct {
	ToolSuccess          bool
	PostconditionsPassed bool
	Warnings             []string
	ContractsEvaluated   []map[string]any
	PolicyError          bool
	RedactedResponse     any
	OutputSuppressed     bool
}
