package workflow

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

type execEvaluator struct{}

func (execEvaluator) Evaluate(ctx context.Context, req EvaluateRequest) (FactResult, error) {
	parsed, err := parseCondition(req.Gate.Condition)
	if err != nil {
		return FactResult{}, err
	}
	shell, flag := "sh", "-c"
	if runtime.GOOS == "windows" {
		shell, flag = "cmd", "/C"
	}
	//nolint:gosec // Workflow exec(...) is an intentional self-authored local evaluator in M1.
	cmd := exec.CommandContext(ctx, shell, flag, parsed.arg)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return FactResult{}, fmt.Errorf("workflow: exec evaluator %q failed: %w", parsed.arg, err)
		}
	}
	return FactResult{
		Passed:    exitCode == parsed.exitCode,
		Evidence:  fmt.Sprintf("exit_code=%d output=%s", exitCode, string(out)),
		Kind:      "exec",
		Condition: parsed.condition,
		Message:   req.Gate.Message,
		StageID:   req.Stage.ID,
		Workflow:  req.Definition.Metadata.Name,
	}, nil
}
