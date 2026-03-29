package guard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/telemetry"
	"github.com/edictum-ai/edictum-go/toolcall"
)

const maxWorkflowApprovalRounds = 32

// handleApproval handles the pending_approval flow.
func (g *Guard) handleApproval(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	pipe *pipeline.CheckPipeline,
	pre pipeline.PreDecision,
	mode, policyVersion string,
	toolCallable func(map[string]any) (any, error),
	args map[string]any,
) (any, error) {
	approved, decision, nextCtx, err := g.resolveApproval(ctx, env2, sess, pre, mode, policyVersion)
	if err != nil {
		return nil, err
	}
	ctx = nextCtx

	if approved {
		if pre.DecisionSource == "workflow" && pre.WorkflowStageID != "" {
			return g.handleWorkflowApproval(ctx, env2, sess, pipe, pre, mode, policyVersion, toolCallable, args)
		}
		g.telemetry.RecordAllowed(ctx, env2.ToolName())
		g.fireOnAllow(env2)
		return g.executeAndPost(ctx, env2, sess, pipe, pre, mode, policyVersion, toolCallable, args)
	}

	// For timeout: span error was already set before ctx was replaced
	// (line 69). This call is a no-op on the timeout path (ctx is
	// Background(), SpanFromContext returns no-op) but correctly marks
	// the span on the human-block path where ctx still carries it.
	telemetry.SetSpanError(trace.SpanFromContext(ctx), "approval blocked")
	g.telemetry.RecordDenial(ctx, env2.ToolName())
	reason := decision.Reason
	if reason == "" {
		reason = pre.Reason
	}
	g.fireOnBlock(env2, reason, pre.DecisionName)
	return nil, &edictum.BlockedError{
		Reason:         reason,
		DecisionSource: pre.DecisionSource,
		DecisionName:   pre.DecisionName,
	}
}

func (g *Guard) resolveApproval(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	pre pipeline.PreDecision,
	mode, policyVersion string,
) (bool, approval.Decision, context.Context, error) {
	if g.approvalBackend == nil {
		telemetry.SetSpanError(trace.SpanFromContext(ctx), "approval backend not configured")
		g.telemetry.RecordDenial(ctx, env2.ToolName())
		return false, approval.Decision{}, ctx, &edictum.BlockedError{
			Reason:         fmt.Sprintf("Approval required but no approval backend configured: %s", pre.Reason),
			DecisionSource: pre.DecisionSource,
			DecisionName:   pre.DecisionName,
		}
	}

	msg := pre.ApprovalMessage
	if msg == "" {
		msg = pre.Reason
	}

	var reqOpts []approval.RequestOption
	if pre.ApprovalTimeout > 0 {
		reqOpts = append(reqOpts, approval.WithTimeout(time.Duration(pre.ApprovalTimeout)*time.Second))
	}
	if pre.ApprovalTimeoutEff != "" {
		reqOpts = append(reqOpts, approval.WithTimeoutEffect(pre.ApprovalTimeoutEff))
	}
	req, err := g.approvalBackend.RequestApproval(ctx, env2.ToolName(), env2.Args(), msg, reqOpts...)
	if err != nil {
		return false, approval.Decision{}, ctx, fmt.Errorf("request approval: %w", err)
	}

	g.emitPreAudit(ctx, env2, sess, audit.ActionCallApprovalRequested, pre, mode, policyVersion)

	decision, err := g.approvalBackend.PollApprovalStatus(ctx, req.ApprovalID())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			if pre.ApprovalTimeoutEff != "allow" {
				telemetry.SetSpanError(trace.SpanFromContext(ctx), "approval timeout")
			} else {
				trace.SpanFromContext(ctx).SetAttributes(
					attribute.Bool("governance.approval_timeout", true))
			}
			decision = approval.Decision{
				Status:    approval.StatusTimeout,
				Timestamp: time.Now().UTC(),
			}
			ctx = context.Background()
		} else {
			return false, approval.Decision{}, ctx, fmt.Errorf("poll approval: %w", err)
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
		g.emitPreAudit(ctx, env2, sess, audit.ActionCallApprovalBlocked, pre, mode, policyVersion)
	default:
		approved = true
		g.emitPreAudit(ctx, env2, sess, audit.ActionCallApprovalGranted, pre, mode, policyVersion)
	}

	return approved, decision, ctx, nil
}

func (g *Guard) handleWorkflowApproval(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	pipe *pipeline.CheckPipeline,
	pre pipeline.PreDecision,
	mode, policyVersion string,
	toolCallable func(map[string]any) (any, error),
	args map[string]any,
) (any, error) {
	g.mu.RLock()
	rt := g.workflowRuntime
	g.mu.RUnlock()
	if rt == nil {
		return nil, fmt.Errorf("workflow approval requested for %q but no workflow runtime configured", pre.WorkflowStageID)
	}

	current := pre
	for round := 0; round < maxWorkflowApprovalRounds; round++ {
		if err := rt.RecordApproval(ctx, sess, current.WorkflowStageID); err != nil {
			return nil, fmt.Errorf("record workflow approval: %w", err)
		}
		nextPre, err := pipe.PreExecute(ctx, env2, sess)
		if err != nil {
			return nil, fmt.Errorf("pre-execute after workflow approval: %w", err)
		}
		if nextPre.Action != "pending_approval" {
			return g.handlePreDecision(ctx, env2, sess, pipe, nextPre, mode, policyVersion, toolCallable, args)
		}
		g.emitWorkflowEvents(ctx, env2, nextPre.WorkflowEvents, mode, policyVersion)
		if nextPre.DecisionSource != "workflow" || nextPre.WorkflowStageID == "" {
			return g.handleApproval(ctx, env2, sess, pipe, nextPre, mode, policyVersion, toolCallable, args)
		}
		current = nextPre
		approved, decision, nextCtx, err := g.resolveApproval(ctx, env2, sess, current, mode, policyVersion)
		if err != nil {
			return nil, err
		}
		ctx = nextCtx
		if !approved {
			telemetry.SetSpanError(trace.SpanFromContext(ctx), "approval blocked")
			g.telemetry.RecordDenial(ctx, env2.ToolName())
			reason := decision.Reason
			if reason == "" {
				reason = current.Reason
			}
			g.fireOnBlock(env2, reason, current.DecisionName)
			return nil, &edictum.BlockedError{
				Reason:         reason,
				DecisionSource: current.DecisionSource,
				DecisionName:   current.DecisionName,
			}
		}
	}

	return nil, fmt.Errorf("workflow: exceeded maximum approval rounds (%d)", maxWorkflowApprovalRounds)
}
