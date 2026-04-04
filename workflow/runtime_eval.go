package workflow

import (
	"context"
	"fmt"

	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

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
	var events []map[string]any
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
			if state.clearWorkflowStatus() {
				changed = true
			}
			eval.Audit = workflowSnapshot(r.definition, state)
			if changed {
				if err := saveState(ctx, sess, r.definition, state); err != nil {
					return Evaluation{}, err
				}
			}
			eval.Events = append(eval.Events, events...)
			return eval, nil
		}

		nextIndex, hasNext := r.nextIndex(stage.ID)
		if invalid != nil && !hasNext {
			changed = r.applyDecisionState(&state, *invalid, env) || changed
			invalid.Audit = workflowSnapshot(r.definition, state)
			if changed {
				if err := saveState(ctx, sess, r.definition, state); err != nil {
					return Evaluation{}, err
				}
			}
			invalid.Events = append(invalid.Events, events...)
			return *invalid, nil
		}
		completion, ok, err := r.evaluateCompletion(ctx, stage, state, env, hasNext)
		if err != nil {
			return Evaluation{}, err
		}
		if !ok {
			if completion.Action != "" {
				changed = r.applyDecisionState(&state, completion, env) || changed
				completion.Audit = workflowSnapshot(r.definition, state)
				if changed {
					if err := saveState(ctx, sess, r.definition, state); err != nil {
						return Evaluation{}, err
					}
				}
				completion.Events = append(completion.Events, events...)
				return completion, nil
			}
			if invalid != nil {
				changed = r.applyDecisionState(&state, *invalid, env) || changed
				invalid.Audit = workflowSnapshot(r.definition, state)
				if changed {
					if err := saveState(ctx, sess, r.definition, state); err != nil {
						return Evaluation{}, err
					}
				}
				invalid.Events = append(invalid.Events, events...)
				return *invalid, nil
			}
			if state.clearWorkflowStatus() {
				changed = true
			}
			completion.Audit = workflowSnapshot(r.definition, state)
			if changed {
				if err := saveState(ctx, sess, r.definition, state); err != nil {
					return Evaluation{}, err
				}
			}
			completion.Events = append(completion.Events, events...)
			return completion, nil
		}

		if invalid != nil {
			nextStage := r.definition.Stages[nextIndex]
			if !stageIsBoundaryOnly(nextStage) && !toolAllowed(nextStage, env) {
				changed = r.applyDecisionState(&state, *invalid, env) || changed
				invalid.Audit = workflowSnapshot(r.definition, state)
				if changed {
					if err := saveState(ctx, sess, r.definition, state); err != nil {
						return Evaluation{}, err
					}
				}
				invalid.Events = append(invalid.Events, events...)
				return *invalid, nil
			}
		}
		if !state.completed(stage.ID) {
			state.CompletedStages = append(state.CompletedStages, stage.ID)
		}
		if !hasNext {
			state.ActiveStage = ""
			state.clearWorkflowStatus()
			events = append(events, workflowProgressEvent("workflow_completed", r.definition, state))
			if err := saveState(ctx, sess, r.definition, state); err != nil {
				return Evaluation{}, err
			}
			return Evaluation{Action: ActionAllow, Audit: workflowSnapshot(r.definition, state), Events: events}, nil
		}
		nextStageID := r.definition.Stages[nextIndex].ID
		state.ActiveStage = nextStageID
		state.clearWorkflowStatus()
		events = append(events, workflowProgressEvent("workflow_stage_advanced", r.definition, state))
		changed = true
	}
}

func (r *Runtime) applyDecisionState(state *State, eval Evaluation, env toolcall.ToolCall) bool {
	switch eval.Action {
	case ActionBlock:
		return state.markBlocked(env, eval.Reason)
	case ActionPendingApproval:
		return state.markPendingApproval(eval.StageID, eval.Reason)
	case ActionAllow:
		return state.clearWorkflowStatus()
	default:
		return false
	}
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
	nextState := state.clone()
	if !nextState.completed(stage.ID) {
		nextState.CompletedStages = append(nextState.CompletedStages, stage.ID)
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
			Parsed:     parsed,
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
