package workflow

const (
	// ActionAllow means the tool call may execute.
	ActionAllow = "allow"
	// ActionBlock means the tool call is denied by the workflow layer.
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
}

// State is the persisted workflow instance state.
type State struct {
	SessionID       string            `json:"session_id" yaml:"session_id"`
	ActiveStage     string            `json:"active_stage" yaml:"active_stage"`
	CompletedStages []string          `json:"completed_stages" yaml:"completed_stages"`
	Approvals       map[string]string `json:"approvals" yaml:"approvals"`
	Evidence        Evidence          `json:"evidence" yaml:"evidence"`
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
