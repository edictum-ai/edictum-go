package guard

import (
	"context"
	"log"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

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
	event.HooksEvaluated = deepCopyRecords(pre.HooksEvaluated)
	event.ContractsEvaluated = deepCopyRecords(pre.ContractsEvaluated)
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
	event.ContractsEvaluated = deepCopyRecords(post.ContractsEvaluated)
	event.SessionAttemptCount = &attempts
	event.SessionExecutionCount = &execs
	event.Mode = mode
	event.PolicyVersion = policyVersion
	event.PolicyError = post.PolicyError

	if err := g.auditSink.Emit(ctx, &event); err != nil {
		log.Printf("audit emit error: %v", err)
	}
}

// emitObservedDenials emits CALL_WOULD_DENY for per-rule observed denials.
func (g *Guard) emitObservedDenials(
	ctx context.Context,
	env2 toolcall.ToolCall,
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
			event.CallIndex = env2.CallIndex()
			event.ParentCallID = env2.ParentCallID()
			event.ToolName = env2.ToolName()
			event.ToolArgs = g.redactionPolicy.RedactArgs(env2.Args())
			event.SideEffect = string(env2.SideEffect())
			event.Environment = env2.Environment()
			event.Principal = principalMap(env2.Principal())
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

// emitObserveResults emits audit events for observe-mode rules.
func (g *Guard) emitObserveResults(
	ctx context.Context,
	env2 toolcall.ToolCall,
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

func principalMap(p *toolcall.Principal) map[string]any {
	if p == nil {
		return nil
	}
	result := map[string]any{}
	if v := p.UserID(); v != "" {
		result["user_id"] = v
	}
	if v := p.ServiceID(); v != "" {
		result["service_id"] = v
	}
	if v := p.OrgID(); v != "" {
		result["org_id"] = v
	}
	if v := p.Role(); v != "" {
		result["role"] = v
	}
	if v := p.TicketRef(); v != "" {
		result["ticket_ref"] = v
	}
	if claims := p.Claims(); claims != nil {
		result["claims"] = claims
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func deepCopyRecords(records []map[string]any) []map[string]any {
	if records == nil {
		return nil
	}
	out := make([]map[string]any, len(records))
	for i, record := range records {
		out[i] = deepCopyRecord(record)
	}
	return out
}

func deepCopyRecord(record map[string]any) map[string]any {
	cp := make(map[string]any, len(record))
	for k, v := range record {
		cp[k] = deepCopyAny(v)
	}
	return cp
}

func deepCopyAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyRecord(val)
	case []any:
		cp := make([]any, len(val))
		for i, item := range val {
			cp[i] = deepCopyAny(item)
		}
		return cp
	default:
		return v
	}
}

// fireOnDeny invokes the on_deny callback, swallowing panics.
func (g *Guard) fireOnDeny(env2 toolcall.ToolCall, reason, name string) {
	if g.onBlock == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_deny callback panicked: %v", r)
		}
	}()
	g.onBlock(env2, reason, name)
}

// fireOnAllow invokes the on_allow callback, swallowing panics.
func (g *Guard) fireOnAllow(env2 toolcall.ToolCall) {
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
func (g *Guard) fireOnPostWarn(env2 toolcall.ToolCall, warnings []string) {
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
