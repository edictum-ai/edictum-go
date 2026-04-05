package adapter

import (
	"context"
	"errors"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/session"
)

func TestWorkflowIntegration_StageAdvancement(t *testing.T) {
	rt := mustWorkflowIntegrationRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: adapter-stage-advance
stages:
  - id: implement
    tools: [Edit]
  - id: review
    tools: [Bash]
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

			sessionID := "stage-advance-" + harness.name
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

			ctx := guard.ContextWithRunOptions(context.Background(), guard.WithParentSessionID("parent-"+harness.name))
			call := newWorkflowIntegrationCall("ok", nil)
			result, err := harness.run(
				ctx,
				g,
				"Bash",
				map[string]any{"command": "go test ./..."},
				call,
				guard.WithSessionID(sessionID),
			)
			if err != nil {
				t.Fatalf("run(Bash): %v", err)
			}
			if result != "ok" {
				t.Fatalf("result = %v, want ok", result)
			}
			if !call.called.Load() {
				t.Fatal("tool was not called")
			}

			state := workflowStateForSession(t, rt, backend, sessionID)
			if state.ActiveStage != "review" {
				t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "review")
			}
			if len(state.CompletedStages) != 1 || state.CompletedStages[0] != "implement" {
				t.Fatalf("CompletedStages = %+v, want [implement]", state.CompletedStages)
			}

			event := requireWorkflowEvent(t, sink.Events(), audit.ActionWorkflowStageAdvanced)
			if event.SessionID != sessionID {
				t.Fatalf("SessionID = %q, want %q", event.SessionID, sessionID)
			}
			if event.ParentSessionID != "parent-"+harness.name {
				t.Fatalf("ParentSessionID = %q, want %q", event.ParentSessionID, "parent-"+harness.name)
			}
			if event.Workflow["active_stage"] != "review" {
				t.Fatalf("workflow.active_stage = %#v, want %q", event.Workflow["active_stage"], "review")
			}
		})
	}
}

func TestWorkflowIntegration_StageBlocking(t *testing.T) {
	rt := mustWorkflowIntegrationRuntime(t, `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: adapter-stage-block
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

			sessionID := "stage-block-" + harness.name
			call := newWorkflowIntegrationCall("ok", nil)
			_, err := harness.run(
				context.Background(),
				g,
				"Edit",
				map[string]any{"path": "src/app.ts"},
				call,
				guard.WithSessionID(sessionID),
			)
			if err == nil {
				t.Fatal("expected workflow block")
			}

			var blocked *edictum.BlockedError
			if !errors.As(err, &blocked) {
				t.Fatalf("expected BlockedError, got %T", err)
			}
			if blocked.Reason != "Read the workflow spec first" {
				t.Fatalf("Reason = %q, want %q", blocked.Reason, "Read the workflow spec first")
			}
			if call.called.Load() {
				t.Fatal("tool executed unexpectedly")
			}

			state := workflowStateForSession(t, rt, backend, sessionID)
			if state.ActiveStage != "read-context" {
				t.Fatalf("ActiveStage = %q, want %q", state.ActiveStage, "read-context")
			}
			if state.BlockedReason != "Read the workflow spec first" {
				t.Fatalf("BlockedReason = %q, want %q", state.BlockedReason, "Read the workflow spec first")
			}

			event := requireWorkflowEvent(t, sink.Events(), audit.ActionCallBlocked)
			if event.SessionID != sessionID {
				t.Fatalf("SessionID = %q, want %q", event.SessionID, sessionID)
			}
			if event.Workflow["blocked_reason"] != "Read the workflow spec first" {
				t.Fatalf("workflow.blocked_reason = %#v, want %q", event.Workflow["blocked_reason"], "Read the workflow spec first")
			}
		})
	}
}
