package workflow

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

const approvedStatus = "approved"

func stateKey(name string) string {
	return "workflow:" + name + ":state"
}

func loadState(ctx context.Context, sess *session.Session, def Definition) (State, error) {
	raw, err := sess.GetValue(ctx, stateKey(def.Metadata.Name))
	if err != nil {
		return State{}, err
	}
	if raw == "" {
		state := State{
			SessionID:   sess.ID(),
			ActiveStage: def.Stages[0].ID,
		}
		state.ensureMaps()
		return state, nil
	}

	var state State
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return State{}, fmt.Errorf("workflow: decode persisted state: %w", err)
	}
	state.SessionID = sess.ID()
	state.ensureMaps()
	if state.ActiveStage != "" {
		if _, ok := def.StageByID(state.ActiveStage); !ok {
			return State{}, fmt.Errorf("workflow: persisted active stage %q does not exist", state.ActiveStage)
		}
	}
	return state, nil
}

func saveState(ctx context.Context, sess *session.Session, def Definition, state State) error {
	state.SessionID = sess.ID()
	state.ensureMaps()
	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("workflow: encode persisted state: %w", err)
	}
	return sess.SetValue(ctx, stateKey(def.Metadata.Name), string(raw))
}

func recordApproval(state *State, stageID string) {
	state.ensureMaps()
	state.Approvals[stageID] = approvedStatus
}

func recordResult(state *State, stageID string, env toolcall.ToolCall) {
	state.ensureMaps()
	switch env.ToolName() {
	case "Read":
		if path := env.FilePath(); path != "" {
			state.Evidence.Reads = append(state.Evidence.Reads, path)
		}
	case "Bash":
		if cmd := env.BashCommand(); cmd != "" {
			state.Evidence.StageCalls[stageID] = append(state.Evidence.StageCalls[stageID], cmd)
		}
	}
}
