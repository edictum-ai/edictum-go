package workflow

import "context"

type fileReadEvaluator struct{}

func (fileReadEvaluator) Evaluate(_ context.Context, req EvaluateRequest) (FactResult, error) {
	parsed, err := parseCondition(req.Gate.Condition)
	if err != nil {
		return FactResult{}, err
	}
	passed := false
	for _, path := range req.State.Evidence.Reads {
		if path == parsed.arg {
			passed = true
			break
		}
	}
	return FactResult{
		Passed:    passed,
		Evidence:  parsed.arg,
		Kind:      "file_read",
		Condition: parsed.condition,
		Message:   req.Gate.Message,
		StageID:   req.Stage.ID,
		Workflow:  req.Definition.Metadata.Name,
	}, nil
}
