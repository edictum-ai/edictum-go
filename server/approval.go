package server

import (
	"context"
	"time"

	"github.com/edictum-ai/edictum-go/approval"
)

// ApprovalBackend implements approval.Backend by delegating to
// the edictum-server approval queue via HTTP.
type ApprovalBackend struct {
	client       *Client
	pollInterval time.Duration
}

// ApprovalOption configures a ApprovalBackend.
type ApprovalOption func(*ApprovalBackend)

// WithPollInterval sets the polling interval for approval status checks.
func WithPollInterval(d time.Duration) ApprovalOption {
	return func(b *ApprovalBackend) { b.pollInterval = d }
}

// NewApprovalBackend creates an approval backend backed by the server.
func NewApprovalBackend(client *Client, opts ...ApprovalOption) *ApprovalBackend {
	b := &ApprovalBackend{
		client:       client,
		pollInterval: 2 * time.Second,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// RequestApproval creates an approval request on the server.
func (b *ApprovalBackend) RequestApproval(
	ctx context.Context,
	toolName string,
	toolArgs map[string]any,
	message string,
	opts ...approval.RequestOption,
) (approval.Request, error) {
	// Apply options to a temporary Request to extract timeout settings.
	tmp := approval.NewRequest("", toolName, toolArgs, message, opts...)
	timeout := int(tmp.Timeout().Seconds())
	if timeout <= 0 {
		timeout = 300
	}
	timeoutEffect := tmp.TimeoutEffect()
	if timeoutEffect == "" {
		timeoutEffect = "block"
	}

	body := map[string]any{
		"agent_id":       b.client.agentID,
		"tool_name":      toolName,
		"tool_args":      toolArgs,
		"message":        message,
		"timeout":        timeout,
		"timeout_action": timeoutEffect,
	}

	resp, err := b.client.Post(ctx, "/v1/approvals", body)
	if err != nil {
		return approval.Request{}, err
	}

	id, _ := resp["id"].(string)
	return approval.NewRequest(id, toolName, toolArgs, message, opts...), nil
}

// PollApprovalStatus polls the server until the approval is resolved
// or the context is cancelled.
func (b *ApprovalBackend) PollApprovalStatus(
	ctx context.Context,
	approvalID string,
) (approval.Decision, error) {
	for {
		resp, err := b.client.Get(ctx, "/v1/approvals/"+approvalID)
		if err != nil {
			// Context cancellation/timeout → return StatusTimeout
			if ctx.Err() != nil {
				return approval.Decision{
					Approved:  false,
					Status:    approval.StatusTimeout,
					Timestamp: time.Now().UTC(),
				}, ctx.Err()
			}
			return approval.Decision{}, err
		}
		if resp == nil {
			return approval.Decision{}, &Error{
				StatusCode: 404,
				Detail:     "approval not found",
			}
		}

		status, _ := resp["status"].(string)
		switch status {
		case "approved":
			approver, _ := resp["decided_by"].(string)
			reason := approvalReason(resp)
			return approval.Decision{
				Approved:  true,
				Approver:  approver,
				Reason:    reason,
				Status:    approval.StatusApproved,
				Timestamp: time.Now().UTC(),
			}, nil

		case "denied", "rejected":
			approver, _ := resp["decided_by"].(string)
			reason := approvalReason(resp)
			return approval.Decision{
				Approved:  false,
				Approver:  approver,
				Reason:    reason,
				Status:    approval.StatusDenied,
				Timestamp: time.Now().UTC(),
			}, nil

		case "timeout", "timed_out":
			return approval.Decision{
				Approved:  false,
				Status:    approval.StatusTimeout,
				Timestamp: time.Now().UTC(),
			}, nil
		}

		// Still pending -- wait and retry.
		timer := time.NewTimer(b.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return approval.Decision{
				Approved:  false,
				Status:    approval.StatusTimeout,
				Timestamp: time.Now().UTC(),
			}, ctx.Err()
		case <-timer.C:
		}
	}
}

func approvalReason(resp map[string]any) string {
	if reason, _ := resp["reason"].(string); reason != "" {
		return reason
	}
	reason, _ := resp["decision_reason"].(string)
	return reason
}
