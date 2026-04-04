package guard

import (
	"context"
	"log"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func (g *Guard) emitWorkflowEvents(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	events []map[string]any,
	mode, policyVersion string,
) {
	for _, record := range events {
		actionName, _ := record["action"].(string)
		workflowData, _ := record["workflow"].(map[string]any)
		if actionName == "" || workflowData == nil {
			continue
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
		event.Workflow = deepCopyRecord(workflowData)
		event.Mode = mode
		event.PolicyVersion = policyVersion

		switch actionName {
		case string(audit.ActionWorkflowStageAdvanced):
			event.Action = audit.ActionWorkflowStageAdvanced
		case string(audit.ActionWorkflowCompleted):
			event.Action = audit.ActionWorkflowCompleted
		case string(audit.ActionWorkflowStateUpdated):
			event.Action = audit.ActionWorkflowStateUpdated
		default:
			continue
		}

		if err := g.auditSink.Emit(ctx, &event); err != nil {
			log.Printf("audit emit error: %v", err)
		}
	}
}
