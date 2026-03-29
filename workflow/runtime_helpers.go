package workflow

import (
	"strings"

	"github.com/edictum-ai/edictum-go/toolcall"
)

func toolAllowed(stage Stage, env toolcall.ToolCall) bool {
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

func workflowProgressEvent(action, name, fromStageID, toStageID string) map[string]any {
	event := map[string]any{
		"action": action,
		"workflow": map[string]any{
			"workflow_name": name,
			"stage_id":      fromStageID,
		},
	}
	if toStageID != "" {
		event["workflow"].(map[string]any)["to_stage_id"] = toStageID
	}
	return event
}

func workflowMetadata(name, stageID, kind, condition string, passed bool, evidence string, extra map[string]any) map[string]any {
	metadata := map[string]any{
		"workflow_name":  name,
		"stage_id":       stageID,
		"gate_kind":      kind,
		"gate_condition": condition,
		"gate_passed":    passed,
		"gate_evidence":  evidence,
	}
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
