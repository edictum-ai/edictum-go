// Package audit provides structured event logging for governance decisions.
package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Action represents the type of governance event.
type Action string

// Audit action types. 10 canonical actions matching Python parity.
const (
	ActionCallDenied            Action = "call_denied"
	ActionCallWouldDeny         Action = "call_would_deny"
	ActionCallAllowed           Action = "call_allowed"
	ActionCallExecuted          Action = "call_executed"
	ActionCallFailed            Action = "call_failed"
	ActionPostconditionWarning  Action = "postcondition_warning"
	ActionCallApprovalRequested Action = "call_approval_requested"
	ActionCallApprovalGranted   Action = "call_approval_granted"
	ActionCallApprovalDenied    Action = "call_approval_denied"
	ActionCallApprovalTimeout   Action = "call_approval_timeout"
)

// AllActions returns all 10 canonical audit actions.
func AllActions() []Action {
	return []Action{
		ActionCallDenied,
		ActionCallWouldDeny,
		ActionCallAllowed,
		ActionCallExecuted,
		ActionCallFailed,
		ActionPostconditionWarning,
		ActionCallApprovalRequested,
		ActionCallApprovalGranted,
		ActionCallApprovalDenied,
		ActionCallApprovalTimeout,
	}
}

// Event represents a structured audit event.
type Event struct {
	SchemaVersion         string           `json:"schema_version"`
	Timestamp             time.Time        `json:"timestamp"`
	RunID                 string           `json:"run_id"`
	CallID                string           `json:"call_id"`
	CallIndex             int              `json:"call_index"`
	ParentCallID          string           `json:"parent_call_id,omitempty"`
	ToolName              string           `json:"tool_name"`
	ToolArgs              map[string]any   `json:"tool_args"`
	SideEffect            string           `json:"side_effect"`
	Environment           string           `json:"environment"`
	Principal             any              `json:"principal,omitempty"`
	Action                Action           `json:"action"`
	DecisionSource        string           `json:"decision_source,omitempty"`
	DecisionName          string           `json:"decision_name,omitempty"`
	Reason                string           `json:"reason,omitempty"`
	HooksEvaluated        []map[string]any `json:"hooks_evaluated"`
	ContractsEvaluated    []map[string]any `json:"contracts_evaluated"`
	ToolSuccess           *bool            `json:"tool_success,omitempty"`
	PostconditionsPassed  *bool            `json:"postconditions_passed,omitempty"`
	DurationMs            *float64         `json:"duration_ms,omitempty"`
	Error                 string           `json:"error,omitempty"`
	ResultSummary         string           `json:"result_summary,omitempty"`
	SessionAttemptCount   *int             `json:"session_attempt_count,omitempty"`
	SessionExecutionCount *int             `json:"session_execution_count,omitempty"`
	Mode                  string           `json:"mode"`
	PolicyVersion         string           `json:"policy_version,omitempty"`
	PolicyError           bool             `json:"policy_error"`
}

const schemaVersion = "0.3.0"

// NewEvent creates a new Event with defaults.
func NewEvent() Event {
	return Event{
		SchemaVersion:      schemaVersion,
		Timestamp:          time.Now().UTC(),
		ToolArgs:           map[string]any{},
		HooksEvaluated:     []map[string]any{},
		ContractsEvaluated: []map[string]any{},
		Mode:               "enforce",
		Action:             ActionCallDenied,
	}
}

// Sink defines the interface for emitting audit events.
type Sink interface {
	Emit(ctx context.Context, event *Event) error
}

// CompositeSink fans out events to multiple sinks.
// Every sink is attempted even if earlier sinks fail. Errors are
// aggregated with errors.Join.
type CompositeSink struct {
	sinks []Sink
}

// NewCompositeSink creates a sink that emits to all provided sinks.
// Panics if no sinks are provided.
func NewCompositeSink(sinks ...Sink) *CompositeSink {
	if len(sinks) == 0 {
		panic("CompositeSink requires at least one sink")
	}
	cp := make([]Sink, len(sinks))
	copy(cp, sinks)
	return &CompositeSink{sinks: cp}
}

// Sinks returns a copy of the wrapped sinks.
func (c *CompositeSink) Sinks() []Sink {
	cp := make([]Sink, len(c.sinks))
	copy(cp, c.sinks)
	return cp
}

// Emit sends the event to all sinks, collecting errors.
// Each sink receives an independent copy to prevent a mutating sink
// from corrupting the event seen by later sinks in the fan-out.
func (c *CompositeSink) Emit(ctx context.Context, event *Event) error {
	var errs []error
	for _, s := range c.sinks {
		cp := *event
		if event.ToolArgs != nil {
			cp.ToolArgs = deepCopyMap(event.ToolArgs)
		}
		if event.HooksEvaluated != nil {
			cp.HooksEvaluated = deepCopyRecordSlice(event.HooksEvaluated)
		}
		if event.ContractsEvaluated != nil {
			cp.ContractsEvaluated = deepCopyRecordSlice(event.ContractsEvaluated)
		}
		if err := s.Emit(ctx, &cp); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// StdoutSink writes events to stdout.
type StdoutSink struct{}

// Emit writes the event to stdout.
func (s *StdoutSink) Emit(_ context.Context, event *Event) error {
	fmt.Printf("[%s] %s tool=%s action=%s\n",
		event.Timestamp.Format(time.RFC3339),
		event.SchemaVersion,
		event.ToolName,
		event.Action,
	)
	return nil
}
