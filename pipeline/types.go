package pipeline

// PreDecision is the result of pre-execution governance checks.
type PreDecision struct {
	Action             string           // "allow", "deny", or "pending_approval"
	Reason             string
	DecisionSource     string
	DecisionName       string
	HooksEvaluated     []map[string]any // Each hook: name, result, reason.
	ContractsEvaluated []map[string]any // Each contract: name, type, passed, message.
	Observed           bool             // True if any per-contract observe deny occurred.
	PolicyError        bool
	ObserveResults     []map[string]any // Observe-mode contract results.
	ApprovalTimeout    int              // Seconds. Default: 300.
	ApprovalTimeoutEff string           // "deny" (default) or "allow".
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
