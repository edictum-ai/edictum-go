package guard

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/trace"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/telemetry"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// executeAndPost executes the tool callable and runs post-execution
// governance checks, audit emission, and callbacks.
func (g *Guard) executeAndPost(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	pipe *pipeline.CheckPipeline,
	pre pipeline.PreDecision,
	mode, policyVersion string,
	toolCallable func(map[string]any) (any, error),
	args map[string]any,
) (any, error) {
	// Execute tool
	var result any
	var toolSuccess bool
	toolResult, toolErr := toolCallable(args)
	if toolErr != nil {
		result = toolErr.Error()
		toolSuccess = false
	} else {
		result = toolResult
		check := g.successCheck
		if check != nil {
			toolSuccess = check(env2.ToolName(), toolResult)
		} else {
			toolSuccess = defaultSuccessCheck(env2.ToolName(), toolResult)
		}
	}

	// Post-execute
	post, postErr := pipe.PostExecute(ctx, env2, result, toolSuccess)
	if postErr != nil {
		return nil, fmt.Errorf("post-execute: %w", postErr)
	}
	post.Workflow = pre.Workflow
	post.WorkflowStageID = pre.WorkflowStageID
	post.WorkflowInvolved = pre.WorkflowInvolved
	var workflowEvents []map[string]any

	if toolSuccess && pre.WorkflowInvolved && pre.WorkflowStageID != "" {
		g.mu.RLock()
		rt := g.workflowRuntime
		g.mu.RUnlock()
		if rt != nil {
			events, err := rt.RecordResult(ctx, sess, pre.WorkflowStageID, env2)
			if err != nil {
				return nil, fmt.Errorf("record workflow evidence: %w", err)
			}
			workflowEvents = append(workflowEvents, events...)
		}
	}
	if pre.WorkflowInvolved {
		g.mu.RLock()
		rt := g.workflowRuntime
		g.mu.RUnlock()
		if rt != nil {
			snapshot, err := rt.Snapshot(ctx, sess)
			if err != nil {
				return nil, fmt.Errorf("workflow snapshot: %w", err)
			}
			post.Workflow = snapshot
		}
	}
	if err := sess.RecordExecution(ctx, env2.ToolName(), toolSuccess); err != nil {
		return nil, fmt.Errorf("record execution: %w", err)
	}

	// Fire on_post_warn callback
	if len(post.Warnings) > 0 {
		g.fireOnPostWarn(env2, post.Warnings)
	}

	// Emit post-execute audit
	postAction := audit.ActionCallExecuted
	if !toolSuccess {
		postAction = audit.ActionCallFailed
	}
	g.emitPostAudit(ctx, env2, sess, postAction, post, mode, policyVersion)
	g.emitWorkflowEvents(ctx, env2, workflowEvents, mode, policyVersion)

	if !toolSuccess {
		// Tool execution failed — Error status reflects the tool outcome.
		// This intentionally overwrites any prior governance status
		// (e.g., approval timeout) because the tool itself failed.
		telemetry.SetSpanError(trace.SpanFromContext(ctx), "tool failed")
		return nil, &edictum.ToolError{Message: fmt.Sprintf("%v", result)}
	}
	// Span status left as Unset (success) — explicitly setting OK would
	// overwrite observed-deny status set earlier in observe mode.
	if post.RedactedResponse != nil {
		return post.RedactedResponse, nil
	}
	return result, nil
}
