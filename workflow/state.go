package workflow

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

const approvedStatus = "approved"
const maxWorkflowEvidenceItems = 1000

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
	state.clearWorkflowStatus()
}

// recordResult records post-success evidence. mcpResult is optional; pass nil for non-MCP calls.
func recordResult(state *State, stageID string, env toolcall.ToolCall, mcpResult ...map[string]any) {
	state.ensureMaps()
	// Record MCP result evidence when provided.
	if len(mcpResult) > 0 && mcpResult[0] != nil {
		existing := state.Evidence.MCPResults[env.ToolName()]
		state.Evidence.MCPResults[env.ToolName()] = appendMCPResultCapped(existing, mcpResult[0], maxWorkflowEvidenceItems)
	}
	// Record file paths from Read and executed commands from Bash.
	switch env.ToolName() {
	case "Read":
		if path := env.FilePath(); path != "" {
			state.Evidence.Reads = appendUniqueCapped(state.Evidence.Reads, path, maxWorkflowEvidenceItems)
			state.LastRecordedEvidence = &EvidenceRecord{
				Tool:      env.ToolName(),
				Summary:   path,
				Timestamp: actionTimestamp(env),
			}
		}
	case "Bash":
		if cmd := env.BashCommand(); cmd != "" {
			state.Evidence.StageCalls[stageID] = appendCapped(state.Evidence.StageCalls[stageID], cmd, maxWorkflowEvidenceItems)
			state.LastRecordedEvidence = &EvidenceRecord{
				Tool:      env.ToolName(),
				Summary:   actionSummary(env),
				Timestamp: actionTimestamp(env),
			}
		}
	}
	state.clearWorkflowStatus()
}

func appendMCPResultCapped(items []map[string]any, item map[string]any, limit int) []map[string]any {
	if len(items) >= limit {
		return items
	}
	// Shallow-copy to prevent the caller from mutating recorded evidence after the fact.
	cp := make(map[string]any, len(item))
	for k, v := range item {
		cp[k] = v
	}
	return append(items, cp)
}

func appendUniqueCapped(items []string, item string, limit int) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return appendCapped(items, item, limit)
}

func appendCapped(items []string, item string, limit int) []string {
	if len(items) >= limit {
		return items
	}
	return append(items, item)
}
