package workflow

import "context"

type commandEvaluator struct{}

func (commandEvaluator) Evaluate(_ context.Context, req EvaluateRequest) (FactResult, error) {
	parsed := req.Parsed
	commands := req.State.Evidence.StageCalls[req.Stage.ID]
	passed := parsed.kind == "command_not_matches"
	for _, command := range commands {
		matched := parsed.regex.MatchString(command)
		if parsed.kind == "command_matches" && matched {
			passed = true
			break
		}
		if parsed.kind == "command_not_matches" && matched {
			passed = false
			break
		}
	}
	return FactResult{
		Passed:    passed,
		Evidence:  joinEvidence(commands),
		Kind:      parsed.kind,
		Condition: parsed.condition,
		Message:   req.Gate.Message,
		StageID:   req.Stage.ID,
		Workflow:  req.Definition.Metadata.Name,
	}, nil
}
