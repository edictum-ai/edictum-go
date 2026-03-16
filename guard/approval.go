package guard

import (
	"context"
	"fmt"
	"time"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
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
		return nil, fmt.Errorf("poll approval: %w", err)
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
		g.fireOnAllow(env2)
		return g.executeAndPost(ctx, env2, sess, pipe, mode, policyVersion, toolCallable, args)
	}

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
