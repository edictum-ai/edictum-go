package workflow

import (
	"context"
	"fmt"
)

type mcpResultMatchesEvaluator struct{}

func (mcpResultMatchesEvaluator) Evaluate(_ context.Context, req EvaluateRequest) (FactResult, error) {
	if len(req.Parsed.extra) != 3 {
		return FactResult{}, fmt.Errorf("workflow: mcp_result_matches: expected 3 extra args, got %d", len(req.Parsed.extra))
	}
	toolName, fieldName, value := req.Parsed.extra[0], req.Parsed.extra[1], req.Parsed.extra[2]
	results := req.State.Evidence.MCPResults[toolName]
	passed := false
	for _, result := range results {
		if fmt.Sprintf("%v", result[fieldName]) == value {
			passed = true
			break
		}
	}
	return FactResult{
		Passed:    passed,
		Evidence:  toolName,
		Kind:      "mcp_result_matches",
		Condition: req.Parsed.condition,
		Message:   req.Gate.Message,
		StageID:   req.Stage.ID,
		Workflow:  req.Definition.Metadata.Name,
	}, nil
}
