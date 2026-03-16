package guard

import (
	"context"
	"log"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
)

// emitPreAudit emits a pre-execution audit event.
func (g *Guard) emitPreAudit(
	ctx context.Context,
	env2 envelope.ToolEnvelope,
	sess *session.Session,
	action audit.Action,
	pre pipeline.PreDecision,
	mode, policyVersion string,
) {
	attempts, _ := sess.AttemptCount(ctx)
	execs, _ := sess.ExecutionCount(ctx)
	event := audit.NewEvent()
	event.RunID = env2.RunID()
	event.CallID = env2.CallID()
	event.ToolName = env2.ToolName()
	event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
	event.SideEffect = string(env2.SideEffect())
	event.Environment = env2.Environment()
	event.Action = action
	event.DecisionSource = pre.DecisionSource
	event.DecisionName = pre.DecisionName
	event.Reason = pre.Reason
	event.HooksEvaluated = len(pre.HooksEvaluated)
	event.ContractsEvaluated = len(pre.ContractsEvaluated)
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
	env2 envelope.ToolEnvelope,
	sess *session.Session,
	action audit.Action,
	post pipeline.PostDecision,
	mode, policyVersion string,
) {
	attempts, _ := sess.AttemptCount(ctx)
	execs, _ := sess.ExecutionCount(ctx)
	event := audit.NewEvent()
	event.RunID = env2.RunID()
	event.CallID = env2.CallID()
	event.ToolName = env2.ToolName()
	event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
	event.SideEffect = string(env2.SideEffect())
	event.Environment = env2.Environment()
	event.Action = action
	event.ToolSuccess = &post.ToolSuccess
	event.PostconditionsPassed = &post.PostconditionsPassed
	event.ContractsEvaluated = len(post.ContractsEvaluated)
	event.SessionAttemptCount = &attempts
	event.SessionExecutionCount = &execs
	event.Mode = mode
	event.PolicyVersion = policyVersion
	event.PolicyError = post.PolicyError

	if err := g.auditSink.Emit(ctx, &event); err != nil {
		log.Printf("audit emit error: %v", err)
	}
}

// emitObservedDenials emits CALL_WOULD_DENY for per-contract observed denials.
func (g *Guard) emitObservedDenials(
	ctx context.Context,
	env2 envelope.ToolEnvelope,
	pre pipeline.PreDecision,
	policyVersion string,
) {
	for _, cr := range pre.ContractsEvaluated {
		observed, _ := cr["observed"].(bool)
		passed, _ := cr["passed"].(bool)
		if observed && !passed {
			event := audit.NewEvent()
			event.RunID = env2.RunID()
			event.CallID = env2.CallID()
			event.ToolName = env2.ToolName()
			event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
			event.SideEffect = string(env2.SideEffect())
			event.Environment = env2.Environment()
			event.Action = audit.ActionCallWouldDeny
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

// emitObserveResults emits audit events for observe-mode contracts.
func (g *Guard) emitObserveResults(
	ctx context.Context,
	env2 envelope.ToolEnvelope,
	pre pipeline.PreDecision,
	policyVersion string,
) {
	for _, sr := range pre.ObserveResults {
		passed, _ := sr["passed"].(bool)
		action := audit.ActionCallAllowed
		if !passed {
			action = audit.ActionCallWouldDeny
		}
		event := audit.NewEvent()
		event.RunID = env2.RunID()
		event.CallID = env2.CallID()
		event.ToolName = env2.ToolName()
		event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
		event.SideEffect = string(env2.SideEffect())
		event.Environment = env2.Environment()
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

// fireOnDeny invokes the on_deny callback, swallowing panics.
func (g *Guard) fireOnDeny(env2 envelope.ToolEnvelope, reason, name string) {
	if g.onDeny == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_deny callback panicked: %v", r)
		}
	}()
	g.onDeny(env2, reason, name)
}

// fireOnAllow invokes the on_allow callback, swallowing panics.
func (g *Guard) fireOnAllow(env2 envelope.ToolEnvelope) {
	if g.onAllow == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_allow callback panicked: %v", r)
		}
	}()
	g.onAllow(env2)
}

// fireOnPostWarn invokes the on_post_warn callback, swallowing panics.
func (g *Guard) fireOnPostWarn(env2 envelope.ToolEnvelope, warnings []string) {
	if g.onPostWarn == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_post_warn callback panicked: %v", r)
		}
	}()
	g.onPostWarn(env2, warnings)
}
