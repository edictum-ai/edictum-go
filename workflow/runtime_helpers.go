package workflow

import (
	"strings"
	"time"

	"github.com/edictum-ai/edictum-go/toolcall"
)

func toolAllowed(stage Stage, env toolcall.ToolCall) bool {
	// M1 keeps tools semantics explicit: omitting tools means the stage is
	// unrestricted, and providing tools makes that list authoritative.
	if len(stage.Tools) == 0 {
		return true
	}
	for _, tool := range stage.Tools {
		if tool == env.ToolName() {
			return true
		}
	}
	return false
}

func stageIsBoundaryOnly(stage Stage) bool {
	return len(stage.Tools) == 0 && len(stage.Checks) == 0 && (stage.Approval != nil || len(stage.Exit) > 0)
}

func workflowProgressEvent(action string, def Definition, state State) map[string]any {
	return map[string]any{
		"action":   action,
		"workflow": workflowSnapshot(def, state),
	}
}

func workflowGateMetadata(def Definition, state State, kind, condition string, passed bool, evidence string, extra map[string]any) map[string]any {
	metadata := workflowSnapshot(def, state)
	metadata["gate_kind"] = kind
	metadata["gate_condition"] = condition
	metadata["gate_passed"] = passed
	metadata["gate_evidence"] = evidence
	for key, value := range extra {
		metadata[key] = value
	}
	return metadata
}

func evaluationFromRecord(action, stageID, reason string, audit map[string]any, record map[string]any) Evaluation {
	return Evaluation{
		Action:  action,
		Reason:  reason,
		StageID: stageID,
		Records: []map[string]any{record},
		Audit:   audit,
	}
}

func (r *Runtime) nextIndex(stageID string) (int, bool) {
	idx := mustIndex(r.definition, stageID)
	next := idx + 1
	return next, next < len(r.definition.Stages)
}

func mustIndex(def Definition, stageID string) int {
	idx, _ := def.StageIndex(stageID)
	return idx
}

func joinEvidence(items []string) string {
	return strings.Join(items, " | ")
}

func stageIDs(stages []Stage) []string {
	result := make([]string, 0, len(stages))
	for _, stage := range stages {
		result = append(result, stage.ID)
	}
	return result
}

func workflowSnapshot(def Definition, state State) map[string]any {
	workflow := map[string]any{
		"name":             def.Metadata.Name,
		"active_stage":     state.ActiveStage,
		"completed_stages": toAnySlice(state.CompletedStages),
		"pending_approval": map[string]any{"required": state.PendingApproval.Required},
	}
	if def.Metadata.Version != "" {
		workflow["version"] = def.Metadata.Version
	}
	if state.BlockedReason != "" {
		workflow["blocked_reason"] = state.BlockedReason
	}
	if state.PendingApproval.StageID != "" {
		workflow["pending_approval"].(map[string]any)["stage_id"] = state.PendingApproval.StageID
	}
	if state.PendingApproval.Message != "" {
		workflow["pending_approval"].(map[string]any)["message"] = state.PendingApproval.Message
	}
	if state.LastRecordedEvidence != nil {
		workflow["last_recorded_evidence"] = map[string]any{
			"tool":      state.LastRecordedEvidence.Tool,
			"summary":   state.LastRecordedEvidence.Summary,
			"timestamp": state.LastRecordedEvidence.Timestamp,
		}
	}
	if state.LastBlockedAction != nil {
		workflow["last_blocked_action"] = map[string]any{
			"tool":      state.LastBlockedAction.Tool,
			"summary":   state.LastBlockedAction.Summary,
			"message":   state.LastBlockedAction.Message,
			"timestamp": state.LastBlockedAction.Timestamp,
		}
	}
	return workflow
}

func actionSummary(env toolcall.ToolCall) string {
	switch {
	case env.BashCommand() != "":
		// Preserve the raw command here for parity with the persisted StageCalls
		// evidence trail; audit arg redaction still happens separately.
		return env.BashCommand()
	case env.FilePath() != "":
		return env.FilePath()
	default:
		return env.ToolName()
	}
}

func actionTimestamp(env toolcall.ToolCall) string {
	if ts := env.Timestamp(); ts != "" {
		return ts
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func toAnySlice(items []string) []any {
	result := make([]any, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	return result
}
