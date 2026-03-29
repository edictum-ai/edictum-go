package workflow

import "context"

type approvalEvaluator struct{}

func (approvalEvaluator) Evaluate(_ context.Context, req EvaluateRequest) (FactResult, error) {
	parsed := req.Parsed
	stageID := parsed.arg
	if stageID == "" {
		stageID = req.Stage.ID
	}
	passed := req.State.Approvals[stageID] == approvedStatus
	return FactResult{
		Passed:    passed,
		Evidence:  req.State.Approvals[stageID],
		Kind:      "approval",
		Condition: parsed.condition,
		Message:   req.Gate.Message,
		StageID:   req.Stage.ID,
		Workflow:  req.Definition.Metadata.Name,
	}, nil
}
