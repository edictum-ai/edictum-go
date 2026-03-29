package workflow

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// Runtime evaluates and persists one workflow definition.
type Runtime struct {
	definition Definition
	mu         sync.Mutex
	evaluators map[string]FactEvaluator
}

// NewRuntime validates a definition and prepares a runtime.
func NewRuntime(def Definition) (*Runtime, error) {
	if err := def.validate(); err != nil {
		return nil, err
	}
	return &Runtime{
		definition: def,
		evaluators: map[string]FactEvaluator{
			"stage_complete":      stageCompleteEvaluator{},
			"file_read":           fileReadEvaluator{},
			"exec":                execEvaluator{},
			"approval":            approvalEvaluator{},
			"command_matches":     commandEvaluator{},
			"command_not_matches": commandEvaluator{},
		},
	}, nil
}

// Definition returns the validated workflow definition.
func (r *Runtime) Definition() Definition {
	return r.definition
}

// State returns the current persisted workflow state.
func (r *Runtime) State(ctx context.Context, sess *session.Session) (State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return loadState(ctx, sess, r.definition)
}

// Reset moves the workflow back to the named stage and clears later state.
func (r *Runtime) Reset(ctx context.Context, sess *session.Session, stageID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	idx, ok := r.definition.StageIndex(stageID)
	if !ok {
		return fmt.Errorf("workflow: unknown reset stage %q", stageID)
	}
	state, err := loadState(ctx, sess, r.definition)
	if err != nil {
		return err
	}
	state.ActiveStage = stageID
	state.CompletedStages = append([]string{}, stageIDs(r.definition.Stages[:idx])...)
	for _, stage := range r.definition.Stages[idx:] {
		delete(state.Approvals, stage.ID)
		delete(state.Evidence.StageCalls, stage.ID)
	}
	if idx == 0 {
		state.Evidence.Reads = []string{}
	}
	return saveState(ctx, sess, r.definition, state)
}

// RecordApproval persists approval for a boundary stage.
func (r *Runtime) RecordApproval(ctx context.Context, sess *session.Session, stageID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.definition.StageByID(stageID); !ok {
		return fmt.Errorf("workflow: unknown approval stage %q", stageID)
	}
	state, err := loadState(ctx, sess, r.definition)
	if err != nil {
		return err
	}
	recordApproval(&state, stageID)
	return saveState(ctx, sess, r.definition, state)
}

// RecordResult persists post-success evidence for the stage that accepted the call.
func (r *Runtime) RecordResult(ctx context.Context, sess *session.Session, stageID string, env toolcall.ToolCall) error {
	if stageID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := loadState(ctx, sess, r.definition)
	if err != nil {
		return err
	}
	recordResult(&state, stageID, env)
	return saveState(ctx, sess, r.definition, state)
}

// Evaluate applies workflow gating before tool execution.
func (r *Runtime) Evaluate(ctx context.Context, sess *session.Session, env toolcall.ToolCall) (Evaluation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := loadState(ctx, sess, r.definition)
	if err != nil {
		return Evaluation{}, err
	}
	if state.ActiveStage == "" {
		return Evaluation{Action: ActionAllow}, nil
	}

	changed := false
	for {
		stage, ok := r.definition.StageByID(state.ActiveStage)
		if !ok {
			return Evaluation{}, fmt.Errorf("workflow: active stage %q not found", state.ActiveStage)
		}

		allowed, eval, invalid, err := r.evaluateCurrentStage(stage, env)
		if err != nil {
			return Evaluation{}, err
		}
		if allowed {
			if changed {
				if err := saveState(ctx, sess, r.definition, state); err != nil {
					return Evaluation{}, err
				}
			}
			return eval, nil
		}

		nextIndex, hasNext := r.nextIndex(stage.ID)
		if invalid != nil && !hasNext {
			return *invalid, nil
		}
		completion, ok, err := r.evaluateCompletion(ctx, stage, state, env, hasNext)
		if err != nil {
			return Evaluation{}, err
		}
		if !ok {
			if completion.Action != "" {
				if changed && completion.Action == ActionPendingApproval {
					if err := saveState(ctx, sess, r.definition, state); err != nil {
						return Evaluation{}, err
					}
				}
				return completion, nil
			}
			if invalid != nil {
				return *invalid, nil
			}
			return completion, nil
		}

		if !state.completed(stage.ID) {
			state.CompletedStages = append(state.CompletedStages, stage.ID)
		}
		if !hasNext {
			state.ActiveStage = ""
			if err := saveState(ctx, sess, r.definition, state); err != nil {
				return Evaluation{}, err
			}
			return Evaluation{Action: ActionAllow}, nil
		}
		state.ActiveStage = r.definition.Stages[nextIndex].ID
		changed = true
	}
}

func (r *Runtime) evaluateCurrentStage(stage Stage, env toolcall.ToolCall) (bool, Evaluation, *Evaluation, error) {
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

func (r *Runtime) evaluateCompletion(ctx context.Context, stage Stage, state State, env toolcall.ToolCall, hasNext bool) (Evaluation, bool, error) {
	if len(stage.Exit) > 0 {
		if failure, ok, err := r.evaluateGates(ctx, stage, state, env, stage.Exit); err != nil || ok {
			return failure, false, err
		}
	}
	if stage.Approval != nil && state.Approvals[stage.ID] != approvedStatus {
		audit := workflowMetadata(r.definition.Metadata.Name, stage.ID, "approval", "stage boundary", false, "", map[string]any{
			"approval_requested_for": stage.ID,
		})
		return evaluationFromRecord(ActionPendingApproval, stage.ID, stage.Approval.Message, audit, gateRecord(FactResult{
			Kind:      "approval",
			Condition: "stage boundary",
			Message:   stage.Approval.Message,
			StageID:   stage.ID,
			Workflow:  r.definition.Metadata.Name,
			ExtraAudit: map[string]any{
				"approval_requested_for": stage.ID,
			},
		}, false)), false, nil
	}
	if !hasNext {
		if len(stage.Exit) > 0 || stage.Approval != nil {
			return Evaluation{Action: ActionAllow}, true, nil
		}
		return Evaluation{}, false, nil
	}
	nextStage := r.definition.Stages[mustIndex(r.definition, stage.ID)+1]
	nextState := state
	if !nextState.completed(stage.ID) {
		nextState.CompletedStages = append(append([]string{}, nextState.CompletedStages...), stage.ID)
	}
	if failure, ok, err := r.evaluateGates(ctx, nextStage, nextState, env, nextStage.Entry); err != nil || ok {
		return failure, false, err
	}
	return Evaluation{}, true, nil
}

func (r *Runtime) evaluateGates(ctx context.Context, stage Stage, state State, env toolcall.ToolCall, gates []Gate) (Evaluation, bool, error) {
	var records []map[string]any
	for _, gate := range gates {
		parsed, err := parseCondition(gate.Condition)
		if err != nil {
			return Evaluation{}, false, err
		}
		evaluator := r.evaluators[parsed.kind]
		result, err := evaluator.Evaluate(ctx, EvaluateRequest{
			Definition: r.definition,
			Stage:      stage,
			Gate:       gate,
			State:      state,
			Call:       env,
		})
		if err != nil {
			return Evaluation{}, false, err
		}
		record := gateRecord(result, result.Passed)
		records = append(records, record)
		if !result.Passed {
			return Evaluation{
				Action:  ActionBlock,
				Reason:  result.Message,
				StageID: stage.ID,
				Records: records,
				Audit:   workflowMetadata(r.definition.Metadata.Name, stage.ID, result.Kind, result.Condition, false, result.Evidence, result.ExtraAudit),
			}, true, nil
		}
	}
	return Evaluation{Records: records}, false, nil
}

func toolAllowed(stage Stage, env toolcall.ToolCall) bool {
	if env.ToolName() == "Read" || env.ToolName() == "Grep" {
		return true
	}
	for _, tool := range stage.Tools {
		if tool == env.ToolName() {
			return true
		}
	}
	return false
}

func evaluateCheck(check Check, env toolcall.ToolCall) (bool, string, error) {
	command := env.BashCommand()
	switch {
	case check.CommandMatches != "":
		re, err := regexp.Compile(check.CommandMatches)
		if err != nil {
			return false, "", fmt.Errorf("workflow: invalid check regex %q: %w", check.CommandMatches, err)
		}
		return re.MatchString(command), check.CommandMatches, nil
	case check.CommandNotMatches != "":
		re, err := regexp.Compile(check.CommandNotMatches)
		if err != nil {
			return false, "", fmt.Errorf("workflow: invalid check regex %q: %w", check.CommandNotMatches, err)
		}
		return !re.MatchString(command), check.CommandNotMatches, nil
	default:
		return true, "", nil
	}
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
