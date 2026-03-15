// Package audit provides structured event logging for governance decisions.
package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Action represents the type of governance event.
type Action string

const (
	ActionCallDenied           Action = "CALL_DENIED"
	ActionCallWouldDeny        Action = "CALL_WOULD_DENY"
	ActionCallAllowed          Action = "CALL_ALLOWED"
	ActionCallExecuted         Action = "CALL_EXECUTED"
	ActionCallFailed           Action = "CALL_FAILED"
	ActionPostconditionWarning Action = "POSTCONDITION_WARNING"
	ActionCallApprovalPending  Action = "CALL_APPROVAL_PENDING"
	ActionCallApprovalGranted  Action = "CALL_APPROVAL_GRANTED"
	ActionCallApprovalDenied   Action = "CALL_APPROVAL_DENIED"
	ActionCallApprovalTimeout  Action = "CALL_APPROVAL_TIMEOUT"
)

// Event represents a structured audit event.
type Event struct {
	SchemaVersion         string         `json:"schema_version"`
	Timestamp             time.Time      `json:"timestamp"`
	RunID                 string         `json:"run_id"`
	CallID                string         `json:"call_id"`
	CallIndex             int            `json:"call_index"`
	ParentCallID          string         `json:"parent_call_id,omitempty"`
	ToolName              string         `json:"tool_name"`
	ToolArgs              map[string]any `json:"tool_args,omitempty"`
	SideEffect            string         `json:"side_effect"`
	Environment           string         `json:"environment"`
	Principal             any            `json:"principal,omitempty"`
	Action                Action         `json:"action"`
	DecisionSource        string         `json:"decision_source,omitempty"`
	DecisionName          string         `json:"decision_name,omitempty"`
	Reason                string         `json:"reason,omitempty"`
	HooksEvaluated        int            `json:"hooks_evaluated"`
	ContractsEvaluated    int            `json:"contracts_evaluated"`
	ToolSuccess           *bool          `json:"tool_success,omitempty"`
	PostconditionsPassed  *bool          `json:"postconditions_passed,omitempty"`
	DurationMs            *float64       `json:"duration_ms,omitempty"`
	Error                 string         `json:"error,omitempty"`
	ResultSummary         string         `json:"result_summary,omitempty"`
	SessionAttemptCount   *int           `json:"session_attempt_count,omitempty"`
	SessionExecutionCount *int           `json:"session_execution_count,omitempty"`
	Mode                  string         `json:"mode"`
	PolicyVersion         string         `json:"policy_version,omitempty"`
	PolicyError           bool           `json:"policy_error"`
}

const schemaVersion = "0.3.0"

// NewEvent creates a new Event with defaults.
func NewEvent() Event {
	return Event{
		SchemaVersion: schemaVersion,
		Timestamp:     time.Now().UTC(),
	}
}

// Sink defines the interface for emitting audit events.
type Sink interface {
	Emit(ctx context.Context, event *Event) error
}

// CompositeSink fans out events to multiple sinks.
type CompositeSink struct {
	sinks []Sink
}

// NewCompositeSink creates a sink that emits to all provided sinks.
func NewCompositeSink(sinks ...Sink) *CompositeSink {
	return &CompositeSink{sinks: sinks}
}

// Emit sends the event to all sinks, collecting errors.
// Each sink receives an independent copy to prevent a mutating sink
// from corrupting the event seen by later sinks in the chain.
func (c *CompositeSink) Emit(ctx context.Context, event *Event) error {
	var errs []error
	for _, s := range c.sinks {
		cp := *event
		if event.ToolArgs != nil {
			cp.ToolArgs = make(map[string]any, len(event.ToolArgs))
			for k, v := range event.ToolArgs {
				cp.ToolArgs[k] = v
			}
		}
		if err := s.Emit(ctx, &cp); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CollectingSink stores events in memory with a ring buffer.
type CollectingSink struct {
	mu     sync.Mutex
	events []Event
	cap    int
	mark   int
}

// NewCollectingSink creates a sink that collects events in memory.
func NewCollectingSink(capacity int) *CollectingSink {
	return &CollectingSink{
		events: make([]Event, 0, capacity),
		cap:    capacity,
		mark:   -1,
	}
}

// Emit adds an event to the buffer. The event is deep-copied to prevent
// post-emit mutation from affecting audit integrity.
func (c *CollectingSink) Emit(_ context.Context, event *Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *event
	if event.ToolArgs != nil {
		cp.ToolArgs = make(map[string]any, len(event.ToolArgs))
		for k, v := range event.ToolArgs {
			cp.ToolArgs[k] = v
		}
	}
	if len(c.events) >= c.cap {
		// Ring buffer: drop oldest
		c.events = append(c.events[1:], cp)
		if c.mark >= 0 {
			c.mark--
		}
	} else {
		c.events = append(c.events, cp)
	}
	return nil
}

// Events returns a copy of all collected events.
func (c *CollectingSink) Events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]Event, len(c.events))
	copy(cp, c.events)
	return cp
}

// Mark sets a mark at the current position.
func (c *CollectingSink) Mark() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mark = len(c.events)
}

// MarkEvictedError is returned when a mark has been evicted from the ring buffer.
type MarkEvictedError struct{}

func (e *MarkEvictedError) Error() string {
	return "mark has been evicted from the ring buffer"
}

// SinceMark returns events since the last mark.
func (c *CollectingSink) SinceMark() ([]Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mark < 0 {
		return nil, &MarkEvictedError{}
	}
	cp := make([]Event, len(c.events)-c.mark)
	copy(cp, c.events[c.mark:])
	return cp, nil
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
