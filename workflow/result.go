package workflow

import "github.com/edictum-ai/edictum-go/toolcall"

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

// PendingApproval is the structured approval-gating state for a workflow.
type PendingApproval struct {
	Required bool   `json:"required" yaml:"required"`
	StageID  string `json:"stage_id,omitempty" yaml:"stage_id,omitempty"`
	Message  string `json:"message,omitempty" yaml:"message,omitempty"`
}

// EvidenceRecord is the most recent successful workflow evidence item.
type EvidenceRecord struct {
	Tool      string `json:"tool" yaml:"tool"`
	Summary   string `json:"summary" yaml:"summary"`
	Timestamp string `json:"timestamp" yaml:"timestamp"`
}

// BlockedAction is the most recent action blocked by the workflow.
type BlockedAction struct {
	Tool      string `json:"tool" yaml:"tool"`
	Summary   string `json:"summary" yaml:"summary"`
	Message   string `json:"message" yaml:"message"`
	Timestamp string `json:"timestamp" yaml:"timestamp"`
}

// State is the persisted workflow instance state.
type State struct {
	SessionID            string            `json:"session_id" yaml:"session_id"`
	ActiveStage          string            `json:"active_stage" yaml:"active_stage"`
	CompletedStages      []string          `json:"completed_stages" yaml:"completed_stages"`
	Approvals            map[string]string `json:"approvals" yaml:"approvals"`
	Evidence             Evidence          `json:"evidence" yaml:"evidence"`
	BlockedReason        string            `json:"blocked_reason,omitempty" yaml:"blocked_reason,omitempty"`
	PendingApproval      PendingApproval   `json:"pending_approval" yaml:"pending_approval"`
	LastRecordedEvidence *EvidenceRecord   `json:"last_recorded_evidence,omitempty" yaml:"last_recorded_evidence,omitempty"`
	LastBlockedAction    *BlockedAction    `json:"last_blocked_action,omitempty" yaml:"last_blocked_action,omitempty"`
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

func (s *State) clearWorkflowStatus() bool {
	changed := false
	if s.BlockedReason != "" {
		s.BlockedReason = ""
		changed = true
	}
	if s.PendingApproval.Required || s.PendingApproval.StageID != "" || s.PendingApproval.Message != "" {
		s.PendingApproval = PendingApproval{}
		changed = true
	}
	return changed
}

func (s *State) clearStageMoveStatus() {
	s.clearWorkflowStatus()
	if s.LastBlockedAction != nil {
		s.LastBlockedAction = nil
	}
}

func (s *State) markBlocked(env toolcall.ToolCall, reason string) bool {
	changed := s.clearWorkflowStatus()
	s.BlockedReason = reason
	if reason != "" {
		changed = true
	}
	next := BlockedAction{
		Tool:      env.ToolName(),
		Summary:   blockedActionSummary(env),
		Message:   reason,
		Timestamp: actionTimestamp(env),
	}
	if s.LastBlockedAction == nil || *s.LastBlockedAction != next {
		blocked := next
		s.LastBlockedAction = &blocked
		changed = true
	}
	return changed
}

func (s *State) markPendingApproval(stageID, message string) bool {
	// Approval pauses are not hard workflow blocks, so they update the
	// pending approval snapshot without overwriting the last blocked action.
	changed := false
	if s.BlockedReason != "" {
		s.BlockedReason = ""
		changed = true
	}
	if !s.PendingApproval.Required || s.PendingApproval.StageID != stageID || s.PendingApproval.Message != message {
		s.PendingApproval = PendingApproval{
			Required: true,
			StageID:  stageID,
			Message:  message,
		}
		changed = true
	}
	return changed
}

func (s *State) clone() State {
	cp := State{
		SessionID:       s.SessionID,
		ActiveStage:     s.ActiveStage,
		CompletedStages: append([]string{}, s.CompletedStages...),
		Approvals:       map[string]string{},
		Evidence: Evidence{
			Reads:      append([]string{}, s.Evidence.Reads...),
			StageCalls: map[string][]string{},
		},
		BlockedReason:   s.BlockedReason,
		PendingApproval: s.PendingApproval,
	}
	for key, value := range s.Approvals {
		cp.Approvals[key] = value
	}
	for key, value := range s.Evidence.StageCalls {
		cp.Evidence.StageCalls[key] = append([]string{}, value...)
	}
	if s.LastRecordedEvidence != nil {
		record := *s.LastRecordedEvidence
		cp.LastRecordedEvidence = &record
	}
	if s.LastBlockedAction != nil {
		blocked := *s.LastBlockedAction
		cp.LastBlockedAction = &blocked
	}
	cp.ensureMaps()
	return cp
}
