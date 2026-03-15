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
	principal     any
	metadata      map[string]any
	createdAt     time.Time
}

// ApprovalID returns the unique approval request ID.
func (r Request) ApprovalID() string { return r.approvalID }

// ToolName returns the tool name.
func (r Request) ToolName() string { return r.toolName }

// Message returns the approval message.
func (r Request) Message() string { return r.message }

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
