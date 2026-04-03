package workflow

const (
	// ActionAllow means the tool call may execute.
	ActionAllow = "allow"
	// ActionBlock means the tool call is blocked by the workflow layer.
	ActionBlock = "block"
	// ActionPendingApproval means the call pauses at a stage boundary.
	ActionPendingApproval = "pending_approval"
)

// Evaluation is the workflow pre-execution decision.
type Evaluation struct {
	Action  string
	Reason  string
	StageID string
	Records []map[string]any
	Audit   map[string]any
	Events  []map[string]any
}

// State is the persisted workflow instance state.
type State struct {
	SessionID         string            `json:"session_id" yaml:"session_id"`
	ActiveStage       string            `json:"active_stage" yaml:"active_stage"`
	CompletedStages   []string          `json:"completed_stages" yaml:"completed_stages"`
	Approvals         map[string]string `json:"approvals" yaml:"approvals"`
	Evidence          Evidence          `json:"evidence" yaml:"evidence"`
	BlockedReason     string            `json:"blocked_reason,omitempty" yaml:"blocked_reason,omitempty"`
	PendingApproval   *PendingApproval  `json:"pending_approval,omitempty" yaml:"pending_approval,omitempty"`
	LastBlockedAction *BlockedAction    `json:"last_blocked_action,omitempty" yaml:"last_blocked_action,omitempty"`
}

// PendingApproval describes an outstanding approval gate.
type PendingApproval struct {
	Required bool   `json:"required" yaml:"required"`
	StageID  string `json:"stage_id" yaml:"stage_id"`
	Message  string `json:"message,omitempty" yaml:"message,omitempty"`
}

// BlockedAction records the most recent tool call that was blocked.
type BlockedAction struct {
	Tool      string `json:"tool" yaml:"tool"`
	Summary   string `json:"summary,omitempty" yaml:"summary,omitempty"`
	Message   string `json:"message,omitempty" yaml:"message,omitempty"`
	Timestamp string `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
}

// Evidence is the persisted runtime evidence set.
type Evidence struct {
	Reads      []string            `json:"reads" yaml:"reads"`
	StageCalls map[string][]string `json:"stage_calls" yaml:"stage_calls"`
}

func (s State) completed(stageID string) bool {
	for _, completed := range s.CompletedStages {
		if completed == stageID {
			return true
		}
	}
	return false
}

func (s *State) ensureMaps() {
	if s.Approvals == nil {
		s.Approvals = map[string]string{}
	}
	if s.Evidence.StageCalls == nil {
		s.Evidence.StageCalls = map[string][]string{}
	}
	if s.Evidence.Reads == nil {
		s.Evidence.Reads = []string{}
	}
	if s.CompletedStages == nil {
		s.CompletedStages = []string{}
	}
}
