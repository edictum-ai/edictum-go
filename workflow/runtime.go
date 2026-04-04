package workflow

import (
	"context"
	"fmt"
	"sync"

	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// Runtime evaluates and persists one workflow definition.
type Runtime struct {
	definition Definition
	// mu serializes all session-backed state reads and writes.
	mu         sync.Mutex
	evaluators map[string]FactEvaluator
}

type runtimeConfig struct {
	execEvaluatorEnabled bool
}

// RuntimeOption configures workflow runtime behavior.
type RuntimeOption func(*runtimeConfig)

// WithExecEvaluatorEnabled opts into trusted exec(...) workflow gates.
func WithExecEvaluatorEnabled() RuntimeOption {
	return func(cfg *runtimeConfig) {
		cfg.execEvaluatorEnabled = true
	}
}

// NewRuntime validates a definition and prepares a runtime.
func NewRuntime(def Definition, opts ...RuntimeOption) (*Runtime, error) {
	if err := def.validate(); err != nil {
		return nil, err
	}
	cfg := &runtimeConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	hasExec, err := usesExecCondition(def)
	if err != nil {
		return nil, err
	}
	if hasExec && !cfg.execEvaluatorEnabled {
		return nil, fmt.Errorf("workflow: exec(...) conditions require WithExecEvaluatorEnabled")
	}

	evaluators := map[string]FactEvaluator{
		"stage_complete":      stageCompleteEvaluator{},
		"file_read":           fileReadEvaluator{},
		"approval":            approvalEvaluator{},
		"command_matches":     commandEvaluator{},
		"command_not_matches": commandEvaluator{},
	}
	if cfg.execEvaluatorEnabled {
		evaluators["exec"] = execEvaluator{}
	}

	return &Runtime{
		definition: def,
		evaluators: evaluators,
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

// Snapshot returns the current workflow context snapshot for audit events.
func (r *Runtime) Snapshot(ctx context.Context, sess *session.Session) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := loadState(ctx, sess, r.definition)
	if err != nil {
		return nil, err
	}
	return workflowSnapshot(r.definition, state), nil
}

// Reset moves the workflow back to the named stage and clears later state.
func (r *Runtime) Reset(ctx context.Context, sess *session.Session, stageID string) ([]map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	idx, ok := r.definition.StageIndex(stageID)
	if !ok {
		return nil, fmt.Errorf("workflow: unknown reset stage %q", stageID)
	}
	state, err := loadState(ctx, sess, r.definition)
	if err != nil {
		return nil, err
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
	state.clearWorkflowStatus()
	state.LastRecordedEvidence = nil
	state.LastBlockedAction = nil
	if err := saveState(ctx, sess, r.definition, state); err != nil {
		return nil, err
	}
	return []map[string]any{workflowProgressEvent("workflow_state_updated", r.definition, state)}, nil
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

// RecordResult persists post-success evidence for the stage that accepted the
// call and completes a terminal workflow stage when the successful call
// satisfies its final exit conditions.
func (r *Runtime) RecordResult(ctx context.Context, sess *session.Session, stageID string, env toolcall.ToolCall) ([]map[string]any, error) {
	if stageID == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := loadState(ctx, sess, r.definition)
	if err != nil {
		return nil, err
	}
	recordResult(&state, stageID, env)
	events, err := r.advanceAfterSuccess(ctx, &state, stageID, env)
	if err != nil {
		return nil, err
	}
	if err := saveState(ctx, sess, r.definition, state); err != nil {
		return nil, err
	}
	return events, nil
}
