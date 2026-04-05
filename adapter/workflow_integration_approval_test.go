package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/session"
)

func TestWorkflowIntegration_ApprovalGate(t *testing.T) {
	rt := mustWorkflowIntegrationRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: adapter-approval-gate
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Approval required before push
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
`)

	for _, harness := range workflowIntegrationHarnesses() {
		t.Run(harness.name, func(t *testing.T) {
			backend := session.NewMemoryBackend()
			approvals := approval.NewMemoryBackend()
			sink := audit.NewCollectingSink(128)
			g := guard.New(
				guard.WithBackend(backend),
				guard.WithWorkflowRuntime(rt),
				guard.WithApprovalBackend(approvals),
				guard.WithAuditSink(sink),
			)

			sessionID := "approval-gate-" + harness.name
			if _, err := harness.run(
				context.Background(),
				g,
				"Edit",
				map[string]any{"path": "src/app.ts"},
				newWorkflowIntegrationCall("ok", nil),
				guard.WithSessionID(sessionID),
			); err != nil {
				t.Fatalf("run(Edit): %v", err)
			}

			bashCall := newWorkflowIntegrationCall("ok", nil)
			resultCh := make(chan workflowIntegrationResult, 1)
			go func() {
				ctx := guard.ContextWithRunOptions(context.Background(), guard.WithParentSessionID("parent-"+harness.name))
				result, err := harness.run(
					ctx,
					g,
					"Bash",
					map[string]any{"command": "git push origin feature-branch"},
					bashCall,
					guard.WithSessionID(sessionID),
				)
				resultCh <- workflowIntegrationResult{result: result, err: err}
			}()

			waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			req, err := approvals.WaitForRequest(waitCtx)
			if err != nil {
				t.Fatalf("WaitForRequest: %v", err)
			}
			if req.SessionID() != sessionID {
				t.Fatalf("request SessionID = %q, want %q", req.SessionID(), sessionID)
			}
			if req.Message() != "Approval required before push" {
				t.Fatalf("request message = %q, want %q", req.Message(), "Approval required before push")
			}
			if err := approvals.Approve(req.ApprovalID(), "reviewer@example.com", "approved"); err != nil {
				t.Fatalf("Approve: %v", err)
			}

			outcome := <-resultCh
			if outcome.err != nil {
				t.Fatalf("run(Bash): %v", outcome.err)
			}
			if outcome.result != "ok" {
				t.Fatalf("result = %v, want ok", outcome.result)
			}
			if !bashCall.called.Load() {
				t.Fatal("tool was not called after approval")
			}

			state := workflowStateForSession(t, rt, backend, sessionID)
			if state.Approvals["review"] != "approved" {
				t.Fatalf("Approvals[review] = %q, want %q", state.Approvals["review"], "approved")
			}

			events := sink.Events()
			requireWorkflowEvent(t, events, audit.ActionCallAsked)
			requireWorkflowEvent(t, events, audit.ActionCallApprovalGranted)
		})
	}
}
