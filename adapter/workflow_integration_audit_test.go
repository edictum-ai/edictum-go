package adapter

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/session"
)

func TestWorkflowIntegration_AuditEmission(t *testing.T) {
	rt := mustWorkflowIntegrationRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: adapter-audit-emission
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("specs/008.md")
        message: Read the workflow spec first
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
`)

	for _, harness := range workflowIntegrationHarnesses() {
		t.Run(harness.name, func(t *testing.T) {
			backend := session.NewMemoryBackend()
			sink := audit.NewCollectingSink(64)
			g := guard.New(
				guard.WithBackend(backend),
				guard.WithWorkflowRuntime(rt),
				guard.WithAuditSink(sink),
			)

			sessionID := "audit-emission-" + harness.name
			if _, err := harness.run(
				context.Background(),
				g,
				"Read",
				map[string]any{"path": "specs/008.md"},
				newWorkflowIntegrationCall("ok", nil),
				guard.WithSessionID(sessionID),
			); err != nil {
				t.Fatalf("run(Read): %v", err)
			}
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

			event := requireWorkflowEvent(t, sink.Events(), audit.ActionWorkflowStageAdvanced)
			if event.Workflow["name"] != "adapter-audit-emission" {
				t.Fatalf("workflow.name = %#v, want %q", event.Workflow["name"], "adapter-audit-emission")
			}
		})
	}
}

func TestAdapterRunOptions_ContextOverridesConstructorDefaults(t *testing.T) {
	for _, harness := range workflowIntegrationHarnesses() {
		t.Run(harness.name, func(t *testing.T) {
			sink := audit.NewCollectingSink(16)
			g := guard.New(guard.WithAuditSink(sink))

			ctx := guard.ContextWithRunOptions(
				context.Background(),
				guard.WithSessionID("ctx-session-"+harness.name),
				guard.WithParentSessionID("ctx-parent-"+harness.name),
			)
			_, err := harness.run(
				ctx,
				g,
				"Read",
				map[string]any{"path": "specs/008.md"},
				newWorkflowIntegrationCall("ok", nil),
				guard.WithSessionID("default-session-"+harness.name),
				guard.WithParentSessionID("default-parent-"+harness.name),
			)
			if err != nil {
				t.Fatalf("run(Read): %v", err)
			}

			events := sink.Events()
			if len(events) < 2 {
				t.Fatalf("events len = %d, want at least 2", len(events))
			}
			for _, event := range events {
				if event.SessionID != "ctx-session-"+harness.name {
					t.Fatalf("SessionID = %q, want %q", event.SessionID, "ctx-session-"+harness.name)
				}
				if event.ParentSessionID != "ctx-parent-"+harness.name {
					t.Fatalf("ParentSessionID = %q, want %q", event.ParentSessionID, "ctx-parent-"+harness.name)
				}
			}
		})
	}
}
