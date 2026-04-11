package workflow

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/edictum-ai/edictum-go/toolcall"
)

const maxWorkflowRegexLength = 10000

// FactEvaluator evaluates one workflow gate condition.
type FactEvaluator interface {
	Evaluate(ctx context.Context, req EvaluateRequest) (FactResult, error)
}

// EvaluateRequest is the input for one gate evaluation.
type EvaluateRequest struct {
	Definition Definition
	Stage      Stage
	Gate       Gate
	Parsed     parsedCondition
	State      State
	Call       toolcall.ToolCall
}

// FactResult is one gate evaluation outcome.
type FactResult struct {
	Passed     bool
	Evidence   string
	Kind       string
	Condition  string
	Message    string
	StageID    string
	Workflow   string
	ExtraAudit map[string]any
}

func usesExecCondition(def Definition) (bool, error) {
	for _, stage := range def.Stages {
		for _, gate := range append(append([]Gate{}, stage.Entry...), stage.Exit...) {
			parsed, err := parseCondition(gate.Condition)
			if err != nil {
				return false, err
			}
			if parsed.kind == "exec" {
				return true, nil
			}
		}
	}
	return false, nil
}

type parsedCondition struct {
	kind      string
	arg       string
	exitCode  int
	regex     *regexp.Regexp
	condition string
	extra     []string // tool, field, value for mcp_result_matches
}

func parseCondition(raw string) (parsedCondition, error) {
	switch {
	case strings.HasPrefix(raw, `stage_complete(`):
		arg, err := parseSingleStringArg(raw, "stage_complete")
		if err != nil {
			return parsedCondition{}, err
		}
		return parsedCondition{kind: "stage_complete", arg: arg, condition: raw}, nil
	case strings.HasPrefix(raw, `file_read(`):
		arg, err := parseSingleStringArg(raw, "file_read")
		if err != nil {
			return parsedCondition{}, err
		}
		return parsedCondition{kind: "file_read", arg: arg, condition: raw}, nil
	case strings.HasPrefix(raw, `approval(`):
		arg, err := parseOptionalStringArg(raw, "approval")
		if err != nil {
			return parsedCondition{}, err
		}
		return parsedCondition{kind: "approval", arg: arg, condition: raw}, nil
	case strings.HasPrefix(raw, `command_matches(`):
		arg, err := parseSingleStringArg(raw, "command_matches")
		if err != nil {
			return parsedCondition{}, err
		}
		re, err := compileWorkflowRegex(arg, raw)
		if err != nil {
			return parsedCondition{}, err
		}
		return parsedCondition{kind: "command_matches", arg: arg, regex: re, condition: raw}, nil
	case strings.HasPrefix(raw, `command_not_matches(`):
		arg, err := parseSingleStringArg(raw, "command_not_matches")
		if err != nil {
			return parsedCondition{}, err
		}
		re, err := compileWorkflowRegex(arg, raw)
		if err != nil {
			return parsedCondition{}, err
		}
		return parsedCondition{kind: "command_not_matches", arg: arg, regex: re, condition: raw}, nil
	case strings.HasPrefix(raw, `exec(`):
		match := execConditionRe.FindStringSubmatch(raw)
		if match == nil {
			return parsedCondition{}, fmt.Errorf("workflow: unsupported exec condition %q", raw)
		}
		command, err := strconv.Unquote(`"` + match[1] + `"`)
		if err != nil {
			return parsedCondition{}, fmt.Errorf("workflow: invalid quoted string in %q: %w", raw, err)
		}
		exitCode := 0
		if match[2] != "" {
			exitCode, err = strconv.Atoi(match[2])
			if err != nil {
				return parsedCondition{}, fmt.Errorf("workflow: invalid exit_code in %q: %w", raw, err)
			}
		}
		return parsedCondition{kind: "exec", arg: command, exitCode: exitCode, condition: raw}, nil
	case strings.HasPrefix(raw, `mcp_result_matches(`):
		match := mcpResultMatchesRe.FindStringSubmatch(raw)
		if match == nil {
			return parsedCondition{}, fmt.Errorf("workflow: unsupported mcp_result_matches condition %q", raw)
		}
		return parsedCondition{
			kind:      "mcp_result_matches",
			arg:       match[1],
			extra:     []string{match[1], match[2], match[3]},
			condition: raw,
		}, nil
	default:
		return parsedCondition{}, fmt.Errorf("workflow: unsupported condition %q", raw)
	}
}

func compileWorkflowRegex(pattern, context string) (*regexp.Regexp, error) {
	if len(pattern) > maxWorkflowRegexLength {
		return nil, fmt.Errorf("workflow: regex in %q exceeds %d characters", context, maxWorkflowRegexLength)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("workflow: invalid regex in %q: %w", context, err)
	}
	return re, nil
}

var (
	singleStringArgRe  = regexp.MustCompile(`^([a-z_]+)\("((?:[^"\\]|\\.)*)"\)$`)
	optionalArgRe      = regexp.MustCompile(`^approval\((?:"((?:[^"\\]|\\.)*)")?\)$`)
	execConditionRe    = regexp.MustCompile(`^exec\("((?:[^"\\]|\\.)*)"(?:,\s*exit_code=(\d+))?\)$`)
	mcpResultMatchesRe = regexp.MustCompile(`^mcp_result_matches\("([^"\\]+)",\s*"([^"\\]+)",\s*"([^"\\]+)"\)$`)
)

func parseSingleStringArg(raw, fn string) (string, error) {
	match := singleStringArgRe.FindStringSubmatch(raw)
	if match == nil || match[1] != fn {
		return "", fmt.Errorf("workflow: unsupported %s condition %q", fn, raw)
	}
	return strconv.Unquote(`"` + match[2] + `"`)
}

func parseOptionalStringArg(raw, fn string) (string, error) {
	match := optionalArgRe.FindStringSubmatch(raw)
	if match == nil || fn != "approval" {
		return "", fmt.Errorf("workflow: unsupported %s condition %q", fn, raw)
	}
	if match[1] == "" {
		return "", nil
	}
	return strconv.Unquote(`"` + match[1] + `"`)
}

func gateRecord(result FactResult, passed bool) map[string]any {
	metadata := map[string]any{
		"workflow_name":  result.Workflow,
		"stage_id":       result.StageID,
		"gate_kind":      result.Kind,
		"gate_condition": result.Condition,
		"gate_passed":    passed,
		"gate_evidence":  result.Evidence,
	}
	for key, value := range result.ExtraAudit {
		metadata[key] = value
	}
	return map[string]any{
		"name":     fmt.Sprintf("%s:%s:%s", result.Workflow, result.StageID, result.Kind),
		"type":     "workflow_gate",
		"passed":   passed,
		"message":  result.Message,
		"metadata": metadata,
	}
}
