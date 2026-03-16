package yaml

import (
	"context"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
)

func compileSession(
	raw map[string]any,
	mode string,
	limits pipeline.OperationLimits,
) contract.SessionContract {
	cid, _ := raw["id"].(string)
	then, _ := raw["then"].(map[string]any)
	msgTemplate := ""
	if then != nil {
		msgTemplate, _ = then["message"].(string)
	}

	isObserve, _ := raw["_shadow"].(bool)
	source := "yaml_session"

	sc := contract.SessionContract{
		Name:   cid,
		Mode:   mode,
		Source: source,
		Check: func(ctx context.Context, s any) (contract.Verdict, error) {
			sess, ok := s.(*session.Session)
			if !ok {
				// Fail-closed: unknown session type cannot be evaluated safely.
				return contract.Fail("Session contract error: unexpected session type",
					map[string]any{"policy_error": true}), nil
			}
			execCount, err := sess.ExecutionCount(ctx)
			if err != nil {
				return contract.Fail("Session error"), err
			}
			if execCount >= limits.MaxToolCalls {
				return contract.Fail(msgTemplate), nil
			}
			attemptCount, err := sess.AttemptCount(ctx)
			if err != nil {
				return contract.Fail("Session error"), err
			}
			if attemptCount >= limits.MaxAttempts {
				return contract.Fail(msgTemplate), nil
			}
			return contract.Pass(), nil
		},
	}

	if isObserve {
		sc.Mode = "observe"
	}

	return sc
}

// mergeSessionLimits merges limits from a session contract into existing
// limits, taking the more restrictive (lower) value.
func mergeSessionLimits(raw map[string]any, existing pipeline.OperationLimits) pipeline.OperationLimits {
	limitsMap, ok := raw["limits"].(map[string]any)
	if !ok {
		return existing
	}

	result := pipeline.OperationLimits{
		MaxAttempts:     existing.MaxAttempts,
		MaxToolCalls:    existing.MaxToolCalls,
		MaxCallsPerTool: make(map[string]int, len(existing.MaxCallsPerTool)),
	}
	for k, v := range existing.MaxCallsPerTool {
		result.MaxCallsPerTool[k] = v
	}

	if v, ok := limitsMap["max_tool_calls"]; ok {
		if n := intOr(v, 0); n > 0 && n < result.MaxToolCalls {
			result.MaxToolCalls = n
		}
	}
	if v, ok := limitsMap["max_attempts"]; ok {
		if n := intOr(v, 0); n > 0 && n < result.MaxAttempts {
			result.MaxAttempts = n
		}
	}
	if perTool, ok := limitsMap["max_calls_per_tool"].(map[string]any); ok {
		for tool, v := range perTool {
			n := intOr(v, 0)
			if n <= 0 {
				continue // Skip zero/negative — would deny all calls to this tool
			}
			if existing, found := result.MaxCallsPerTool[tool]; found {
				if n < existing {
					result.MaxCallsPerTool[tool] = n
				}
			} else {
				result.MaxCallsPerTool[tool] = n
			}
		}
	}

	return result
}
