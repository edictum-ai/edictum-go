package workflow

import "context"

type stageCompleteEvaluator struct{}

func (stageCompleteEvaluator) Evaluate(_ context.Context, req EvaluateRequest) (FactResult, error) {
	parsed := req.Parsed
	passed := req.State.completed(parsed.arg)
	return FactResult{
		Passed:    passed,
		Evidence:  parsed.arg,
		Kind:      "stage_complete",
		Condition: parsed.condition,
		Message:   req.Gate.Message,
		StageID:   req.Stage.ID,
		Workflow:  req.Definition.Metadata.Name,
	}, nil
}
