package workflow

import (
	"strings"

	"github.com/edictum-ai/edictum-go/toolcall"
)

func (r *Runtime) evaluateCurrentStage(stage Stage, env toolcall.ToolCall) (bool, Evaluation, *Evaluation, error) {
	if stageIsBoundaryOnly(stage) {
		return false, Evaluation{}, nil, nil
	}
	if !toolAllowed(stage, env) {
		block := evaluationFromRecord(ActionBlock, stage.ID, "Tool is not allowed in this workflow stage", workflowMetadata(r.definition.Metadata.Name, stage.ID, "tools", strings.Join(stage.Tools, ","), false, env.ToolName(), nil), gateRecord(FactResult{
			Kind:      "tools",
			Condition: strings.Join(stage.Tools, ","),
			Message:   "Tool is not allowed in this workflow stage",
			StageID:   stage.ID,
			Workflow:  r.definition.Metadata.Name,
			Evidence:  env.ToolName(),
		}, false))
		return false, Evaluation{}, &block, nil
	}
	for _, check := range stage.Checks {
		passed, condition, err := evaluateCheck(check, env)
		if err != nil {
			return false, Evaluation{}, nil, err
		}
		if !passed {
			block := evaluationFromRecord(ActionBlock, stage.ID, check.Message, workflowMetadata(r.definition.Metadata.Name, stage.ID, "check", condition, false, env.BashCommand(), nil), gateRecord(FactResult{
				Kind:      "check",
				Condition: condition,
				Message:   check.Message,
				StageID:   stage.ID,
				Workflow:  r.definition.Metadata.Name,
				Evidence:  env.BashCommand(),
			}, false))
			return false, Evaluation{}, &block, nil
		}
	}
	condition := "tools"
	if len(stage.Tools) > 0 {
		condition = strings.Join(stage.Tools, ",")
	}
	record := gateRecord(FactResult{
		Kind:      "tools",
		Condition: condition,
		Message:   "tool allowed in active stage",
		StageID:   stage.ID,
		Workflow:  r.definition.Metadata.Name,
		Evidence:  env.ToolName(),
	}, true)
	return true, evaluationFromRecord(ActionAllow, stage.ID, "", workflowMetadata(r.definition.Metadata.Name, stage.ID, "tools", condition, true, env.ToolName(), nil), record), nil, nil
}
