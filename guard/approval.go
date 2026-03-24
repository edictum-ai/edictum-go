package guard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/trace"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/telemetry"
)

// handleApproval handles the pending_approval flow.
func (g *Guard) handleApproval(
	ctx context.Context,
	env2 envelope.ToolEnvelope,
	sess *session.Session,
	pipe *pipeline.GovernancePipeline,
	pre pipeline.PreDecision,
	mode, policyVersion string,
	toolCallable func(map[string]any) (any, error),
	args map[string]any,
) (any, error) {
	if g.approvalBackend == nil {
		return nil, &edictum.DeniedError{
			Reason:         fmt.Sprintf("Approval required but no approval backend configured: %s", pre.Reason),
			DecisionSource: pre.DecisionSource,
			DecisionName:   pre.DecisionName,
		}
	}

	msg := pre.ApprovalMessage
	if msg == "" {
		msg = pre.Reason
	}

	// Propagate per-contract timeout settings to the approval backend.
	var reqOpts []approval.RequestOption
	if pre.ApprovalTimeout > 0 {
		reqOpts = append(reqOpts, approval.WithTimeout(time.Duration(pre.ApprovalTimeout)*time.Second))
	}
	if pre.ApprovalTimeoutEff != "" {
		reqOpts = append(reqOpts, approval.WithTimeoutEffect(pre.ApprovalTimeoutEff))
	}
	req, err := g.approvalBackend.RequestApproval(ctx, env2.ToolName(), env2.Args(), msg, reqOpts...)
	if err != nil {
		return nil, fmt.Errorf("request approval: %w", err)
	}

	g.emitPreAudit(ctx, env2, sess, audit.ActionCallApprovalRequested, pre, mode, policyVersion)

	decision, err := g.approvalBackend.PollApprovalStatus(ctx, req.ApprovalID())
	if err != nil {
		// Context cancellation/deadline → treat as approval timeout.
		// Apply timeout_effect rather than propagating the raw error.
		// Use a fresh context for post-timeout operations (audit, execution)
		// since the original context is expired.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			// Mark the span BEFORE dropping the context that carries it.
			// After ctx is replaced with Background(), SpanFromContext
			// returns a no-op and the timeout would be invisible in traces.
			telemetry.SetSpanError(trace.SpanFromContext(ctx), "approval timeout")
			decision = approval.Decision{
				Status:    approval.StatusTimeout,
				Timestamp: time.Now().UTC(),
			}
			ctx = context.Background()
		} else {
			return nil, fmt.Errorf("poll approval: %w", err)
		}
	}

	approved := false
	switch {
	case decision.Status == approval.StatusTimeout:
		g.emitPreAudit(ctx, env2, sess, audit.ActionCallApprovalTimeout, pre, mode, policyVersion)
		if pre.ApprovalTimeoutEff == "allow" {
			approved = true
		}
	case !decision.Approved:
		g.emitPreAudit(ctx, env2, sess, audit.ActionCallApprovalDenied, pre, mode, policyVersion)
	default:
		approved = true
		g.emitPreAudit(ctx, env2, sess, audit.ActionCallApprovalGranted, pre, mode, policyVersion)
	}

	if approved {
		g.telemetry.RecordAllowed(ctx, env2.ToolName())
		g.fireOnAllow(env2)
		return g.executeAndPost(ctx, env2, sess, pipe, mode, policyVersion, toolCallable, args)
	}

	// For timeout: span error was already set before ctx was replaced
	// (line 69). This call is a no-op on the timeout path (ctx is
	// Background(), SpanFromContext returns no-op) but correctly marks
	// the span on the human-denial path where ctx still carries it.
	telemetry.SetSpanError(trace.SpanFromContext(ctx), "approval denied")
	g.telemetry.RecordDenial(ctx, env2.ToolName())
	reason := decision.Reason
	if reason == "" {
		reason = pre.Reason
	}
	g.fireOnDeny(env2, reason, pre.DecisionName)
	return nil, &edictum.DeniedError{
		Reason:         reason,
		DecisionSource: pre.DecisionSource,
		DecisionName:   pre.DecisionName,
	}
}
