package workflow

import (
	"context"
	"fmt"

	"github.com/edictum-ai/edictum-go/toolcall"
)

func (r *Runtime) advanceAfterSuccess(ctx context.Context, state *State, stageID string, env toolcall.ToolCall) ([]map[string]any, error) {
	if state.ActiveStage != stageID {
		return nil, nil
	}
	stage, ok := r.definition.StageByID(stageID)
	if !ok {
		return nil, fmt.Errorf("workflow: active stage %q not found", stageID)
	}
	// v0.18: terminal stages never auto-advance via RecordResult.
	// Their exit evaluation happens on the next Evaluate call.
	if stage.Terminal {
		return nil, nil
	}
	if _, hasNext := r.nextIndex(stage.ID); hasNext {
		return nil, nil
	}
	if len(stage.Exit) == 0 && stage.Approval == nil {
		return nil, nil
	}
	if len(stage.Exit) > 0 {
		if _, blocked, err := r.evaluateGates(ctx, stage, *state, env, stage.Exit); err != nil {
			return nil, err
		} else if blocked {
			return nil, nil
		}
	}
	if stage.Approval != nil && state.Approvals[stage.ID] != approvedStatus {
		return nil, nil
	}
	if !state.completed(stage.ID) {
		state.CompletedStages = append(state.CompletedStages, stage.ID)
	}
	state.ActiveStage = ""
	state.clearWorkflowStatus()
	return []map[string]any{workflowProgressEvent("workflow_completed", r.definition, *state)}, nil
}

func evaluateCheck(check Check, env toolcall.ToolCall) (bool, string, error) {
	command := env.BashCommand()
	switch {
	case check.CommandMatches != "":
		return check.commandMatchesRE.MatchString(command), check.CommandMatches, nil
	case check.CommandNotMatches != "":
		return !check.commandNotRE.MatchString(command), check.CommandNotMatches, nil
	default:
		return true, "", nil
	}
}
