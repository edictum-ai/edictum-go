// Package approval provides human-in-the-loop authorization for tool calls.
package approval

import (
	"context"
	"time"
)

// Status represents the current state of an approval request.
type Status string

// Approval status values.
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusTimeout  Status = "timeout"
)

// Request represents a pending approval request.
type Request struct {
	approvalID    string
	sessionID     string
	toolName      string
	toolArgs      map[string]any
	message       string
	timeout       time.Duration
	timeoutEffect string
	principal     any // any: avoids import cycle with toolcall.Principal; concrete type varies by integration
	metadata      map[string]any
	createdAt     time.Time
}

// ApprovalID returns the unique approval request ID.
func (r Request) ApprovalID() string { return r.approvalID }

// SessionID returns the session associated with the request.
func (r Request) SessionID() string { return r.sessionID }

// ToolName returns the tool name.
func (r Request) ToolName() string { return r.toolName }

// ToolArgs returns a defensive deep copy of the tool arguments.
func (r Request) ToolArgs() map[string]any {
	return deepCopyMap(r.toolArgs)
}

// Message returns the approval message.
func (r Request) Message() string { return r.message }

// Principal returns the principal associated with the request.
// Returns any to avoid an import cycle with the envelope package;
// concrete type is *toolcall.Principal when set by the pipeline.
func (r Request) Principal() any { return r.principal }

// Metadata returns a defensive deep copy of the request metadata.
func (r Request) Metadata() map[string]any {
	return deepCopyMap(r.metadata)
}

// CreatedAt returns the time the request was created.
func (r Request) CreatedAt() time.Time { return r.createdAt }

// Timeout returns the approval timeout duration.
func (r Request) Timeout() time.Duration { return r.timeout }

// TimeoutEffect returns the effect when timeout occurs ("block" or "allow").
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

// WithSessionID sets the workflow session ID on the request.
func WithSessionID(sessionID string) RequestOption {
	return func(r *Request) { r.sessionID = sessionID }
}

// WithTimeoutEffect sets the effect when timeout occurs ("block" or "allow").
func WithTimeoutEffect(effect string) RequestOption {
	return func(r *Request) { r.timeoutEffect = effect }
}

// deepCopyMap recursively copies a map[string]any.
// Local to approval to avoid importing internal/deepcopy from a public package.
func deepCopyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = deepCopyValue(v)
	}
	return dst
}

func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyMap(val)
	case []any:
		cp := make([]any, len(val))
		for i, elem := range val {
			cp[i] = deepCopyValue(elem)
		}
		return cp
	default:
		return v
	}
}

// NewRequest creates a Request with the given fields. Required for
// Backend implementations outside the approval package, since Request
// fields are unexported for immutability.
func NewRequest(approvalID, toolName string, toolArgs map[string]any, message string, opts ...RequestOption) Request {
	r := Request{
		approvalID: approvalID,
		toolName:   toolName,
		toolArgs:   deepCopyMap(toolArgs),
		message:    message,
		createdAt:  time.Now().UTC(),
	}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}
