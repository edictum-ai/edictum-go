package guard

import (
	"context"
	"log"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

const parentSessionIDMetadataKey = "parent_session_id"

// emitPreAudit emits a pre-execution audit event.
func (g *Guard) emitPreAudit(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	action audit.Action,
	pre pipeline.PreDecision,
	mode, policyVersion string,
) {
	attempts, _ := sess.AttemptCount(ctx)
	execs, _ := sess.ExecutionCount(ctx)
	event := audit.NewEvent()
	event.RunID = env2.RunID()
	event.SessionID = sess.ID()
	event.ParentSessionID = parentSessionID(env2)
	event.CallID = env2.CallID()
	event.CallIndex = env2.CallIndex()
	event.ParentCallID = env2.ParentCallID()
	event.ToolName = env2.ToolName()
	event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
	event.SideEffect = string(env2.SideEffect())
	event.Environment = env2.Environment()
	event.Principal = principalMap(env2.Principal())
	event.Action = action
	event.DecisionSource = pre.DecisionSource
	event.DecisionName = pre.DecisionName
	event.Reason = pre.Reason
	event.Workflow = deepCopyRecord(pre.Workflow)
	event.HooksEvaluated = deepCopyRecords(pre.HooksEvaluated)
	event.RulesEvaluated = deepCopyRecords(pre.RulesEvaluated)
	event.SessionAttemptCount = &attempts
	event.SessionExecutionCount = &execs
	event.Mode = mode
	event.PolicyVersion = policyVersion
	event.PolicyError = pre.PolicyError

	if err := g.auditSink.Emit(ctx, &event); err != nil {
		log.Printf("audit emit error: %v", err)
	}
}

// emitPostAudit emits a post-execution audit event.
func (g *Guard) emitPostAudit(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	action audit.Action,
	post pipeline.PostDecision,
	mode, policyVersion string,
) {
	attempts, _ := sess.AttemptCount(ctx)
	execs, _ := sess.ExecutionCount(ctx)
	event := audit.NewEvent()
	event.RunID = env2.RunID()
	event.SessionID = sess.ID()
	event.ParentSessionID = parentSessionID(env2)
	event.CallID = env2.CallID()
	event.CallIndex = env2.CallIndex()
	event.ParentCallID = env2.ParentCallID()
	event.ToolName = env2.ToolName()
	event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
	event.SideEffect = string(env2.SideEffect())
	event.Environment = env2.Environment()
	event.Principal = principalMap(env2.Principal())
	event.Action = action
	event.ToolSuccess = &post.ToolSuccess
	event.PostconditionsPassed = &post.PostconditionsPassed
	event.Workflow = deepCopyRecord(post.Workflow)
	event.RulesEvaluated = deepCopyRecords(post.RulesEvaluated)
	event.SessionAttemptCount = &attempts
	event.SessionExecutionCount = &execs
	event.Mode = mode
	event.PolicyVersion = policyVersion
	event.PolicyError = post.PolicyError

	if err := g.auditSink.Emit(ctx, &event); err != nil {
		log.Printf("audit emit error: %v", err)
	}
}

// emitObservedDenials emits CALL_WOULD_BLOCK for per-rule observed denials.
func (g *Guard) emitObservedDenials(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	pre pipeline.PreDecision,
	policyVersion string,
) {
	for _, cr := range pre.RulesEvaluated {
		observed, _ := cr["observed"].(bool)
		passed, _ := cr["passed"].(bool)
		if observed && !passed {
			event := audit.NewEvent()
			event.RunID = env2.RunID()
			event.SessionID = sess.ID()
			event.ParentSessionID = parentSessionID(env2)
			event.CallID = env2.CallID()
			event.CallIndex = env2.CallIndex()
			event.ParentCallID = env2.ParentCallID()
			event.ToolName = env2.ToolName()
			event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
			event.SideEffect = string(env2.SideEffect())
			event.Environment = env2.Environment()
			event.Principal = principalMap(env2.Principal())
			event.Action = audit.ActionCallWouldBlock
			event.DecisionSource = "precondition"
			if name, ok := cr["name"].(string); ok {
				event.DecisionName = name
			}
			if msg, ok := cr["message"].(string); ok {
				event.Reason = msg
			}
			event.Mode = "observe"
			event.PolicyVersion = policyVersion
			event.PolicyError = pre.PolicyError
			if err := g.auditSink.Emit(ctx, &event); err != nil {
				log.Printf("audit emit error: %v", err)
			}
		}
	}
}

// emitObserveResults emits audit events for observe-mode rules.
func (g *Guard) emitObserveResults(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	pre pipeline.PreDecision,
	policyVersion string,
) {
	for _, sr := range pre.ObserveResults {
		passed, _ := sr["passed"].(bool)
		action := audit.ActionCallAllowed
		if !passed {
			action = audit.ActionCallWouldBlock
		}
		event := audit.NewEvent()
		event.RunID = env2.RunID()
		event.SessionID = sess.ID()
		event.ParentSessionID = parentSessionID(env2)
		event.CallID = env2.CallID()
		event.CallIndex = env2.CallIndex()
		event.ParentCallID = env2.ParentCallID()
		event.ToolName = env2.ToolName()
		event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
		event.SideEffect = string(env2.SideEffect())
		event.Environment = env2.Environment()
		event.Principal = principalMap(env2.Principal())
		event.Action = action
		if src, ok := sr["source"].(string); ok {
			event.DecisionSource = src
		}
		if name, ok := sr["name"].(string); ok {
			event.DecisionName = name
		}
		if msg, ok := sr["message"].(string); ok {
			event.Reason = msg
		}
		event.Mode = "observe"
		event.PolicyVersion = policyVersion
		if err := g.auditSink.Emit(ctx, &event); err != nil {
			log.Printf("audit emit error: %v", err)
		}
	}
}

func parentSessionID(env2 toolcall.ToolCall) string {
	if value, ok := env2.Metadata()[parentSessionIDMetadataKey].(string); ok {
		return value
	}
	return ""
}
