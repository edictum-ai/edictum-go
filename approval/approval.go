// Package approval provides human-in-the-loop authorization for tool calls.
package approval

import (
	"context"
	"time"
)

// Status represents the current state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusTimeout  Status = "timeout"
)

// Request represents a pending approval request.
type Request struct {
	approvalID    string
	toolName      string
	toolArgs      map[string]any
	message       string
	timeout       time.Duration
	timeoutEffect string
	principal     any // any: avoids import cycle with envelope.Principal; concrete type varies by integration
	metadata      map[string]any
	createdAt     time.Time
}

// ApprovalID returns the unique approval request ID.
func (r Request) ApprovalID() string { return r.approvalID }

// ToolName returns the tool name.
func (r Request) ToolName() string { return r.toolName }

// ToolArgs returns a defensive copy of the tool arguments.
func (r Request) ToolArgs() map[string]any {
	if r.toolArgs == nil {
		return nil
	}
	cp := make(map[string]any, len(r.toolArgs))
	for k, v := range r.toolArgs {
		cp[k] = v
	}
	return cp
}

// Message returns the approval message.
func (r Request) Message() string { return r.message }

// Principal returns the principal associated with the request.
// Returns any to avoid an import cycle with the envelope package;
// concrete type is *envelope.Principal when set by the pipeline.
func (r Request) Principal() any { return r.principal }

// Metadata returns a defensive copy of the request metadata.
func (r Request) Metadata() map[string]any {
	if r.metadata == nil {
		return nil
	}
	cp := make(map[string]any, len(r.metadata))
	for k, v := range r.metadata {
		cp[k] = v
	}
	return cp
}

// CreatedAt returns the time the request was created.
func (r Request) CreatedAt() time.Time { return r.createdAt }

// Timeout returns the approval timeout duration.
func (r Request) Timeout() time.Duration { return r.timeout }

// TimeoutEffect returns the effect when timeout occurs ("deny" or "allow").
func (r Request) TimeoutEffect() string { return r.timeoutEffect }

// Decision represents the outcome of an approval request.
type Decision struct {
	Approved  bool
	Approver  string
	Reason    string
	Status    Status
	Timestamp time.Time
}

// Backend defines the interface for approval request management.
type Backend interface {
	RequestApproval(ctx context.Context, toolName string, toolArgs map[string]any, message string, opts ...RequestOption) (Request, error)
	PollApprovalStatus(ctx context.Context, approvalID string) (Decision, error)
}

// RequestOption configures an approval request.
type RequestOption func(*Request)

// WithTimeout sets the approval timeout.
func WithTimeout(d time.Duration) RequestOption {
	return func(r *Request) { r.timeout = d }
}

// WithTimeoutEffect sets the effect when timeout occurs ("deny" or "allow").
func WithTimeoutEffect(effect string) RequestOption {
	return func(r *Request) { r.timeoutEffect = effect }
}
