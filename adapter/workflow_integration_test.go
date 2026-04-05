package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/adapter/adkgo"
	"github.com/edictum-ai/edictum-go/adapter/eino"
	"github.com/edictum-ai/edictum-go/adapter/genkit"
	"github.com/edictum-ai/edictum-go/adapter/langchaingo"
	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/workflow"
)

type workflowIntegrationHarness struct {
	name string
	run  func(context.Context, *guard.Guard, string, map[string]any, *workflowIntegrationCall, ...guard.RunOption) (any, error)
}

type workflowIntegrationCall struct {
	result any
	err    error
	called atomic.Bool
}

type workflowIntegrationResult struct {
	result any
	err    error
}

func workflowIntegrationHarnesses() []workflowIntegrationHarness {
	return []workflowIntegrationHarness{
		{name: "adkgo", run: runADKIntegration},
		{name: "eino", run: runEinoIntegration},
		{name: "genkit", run: runGenkitIntegration},
		{name: "langchaingo", run: runLangChainGoIntegration},
	}
}

func newWorkflowIntegrationCall(result any, err error) *workflowIntegrationCall {
	return &workflowIntegrationCall{result: result, err: err}
}

func (c *workflowIntegrationCall) mapCallable() func(context.Context, map[string]any) (any, error) {
	return func(_ context.Context, _ map[string]any) (any, error) {
		c.called.Store(true)
		return c.result, c.err
	}
}

func (c *workflowIntegrationCall) langChainCallable() func(context.Context, string) (string, error) {
	return func(_ context.Context, _ string) (string, error) {
		c.called.Store(true)
		if c.err != nil {
			return "", c.err
		}
		if c.result == nil {
			return "", nil
		}
		return fmt.Sprintf("%v", c.result), nil
	}
}

func runADKIntegration(ctx context.Context, g *guard.Guard, toolName string, args map[string]any, call *workflowIntegrationCall, opts ...guard.RunOption) (any, error) {
	return adkgo.New(g, opts...).WrapTool(toolName, call.mapCallable())(ctx, args)
}

func runEinoIntegration(ctx context.Context, g *guard.Guard, toolName string, args map[string]any, call *workflowIntegrationCall, opts ...guard.RunOption) (any, error) {
	return eino.New(g, opts...).WrapTool(toolName, call.mapCallable())(ctx, args)
}

func runGenkitIntegration(ctx context.Context, g *guard.Guard, toolName string, args map[string]any, call *workflowIntegrationCall, opts ...guard.RunOption) (any, error) {
	return genkit.New(g, opts...).WrapTool(toolName, call.mapCallable())(ctx, args)
}

func runLangChainGoIntegration(ctx context.Context, g *guard.Guard, toolName string, args map[string]any, call *workflowIntegrationCall, opts ...guard.RunOption) (any, error) {
	input, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return langchaingo.New(g, opts...).WrapTool(toolName, call.langChainCallable())(ctx, string(input))
}

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
			editCall := newWorkflowIntegrationCall("ok", nil)
			if _, err := harness.run(
				context.Background(),
				g,
				"Edit",
				map[string]any{"path": "src/app.ts"},
				editCall,
				guard.WithSessionID(sessionID),
			); err != nil {
				t.Fatalf("run(Edit): %v", err)
			}

			call := newWorkflowIntegrationCall("ok", nil)
			ctx := guard.ContextWithRunOptions(
				context.Background(),
				guard.WithParentSessionID("parent-"+harness.name),
			)

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
			editCall := newWorkflowIntegrationCall("ok", nil)
			if _, err := harness.run(
				context.Background(),
				g,
				"Edit",
				map[string]any{"path": "src/app.ts"},
				editCall,
				guard.WithSessionID(sessionID),
			); err != nil {
				t.Fatalf("run(Edit): %v", err)
			}

			bashCall := newWorkflowIntegrationCall("ok", nil)
			resultCh := make(chan workflowIntegrationResult, 1)
			go func() {
				ctx := guard.ContextWithRunOptions(
					context.Background(),
					guard.WithParentSessionID("parent-"+harness.name),
				)
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

			_, err := harness.run(
				context.Background(),
				g,
				"Read",
				map[string]any{"path": "specs/008.md"},
				newWorkflowIntegrationCall("ok", nil),
				guard.WithSessionID("audit-emission-"+harness.name),
			)
			if err != nil {
				t.Fatalf("run(Read): %v", err)
			}
			_, err = harness.run(
				context.Background(),
				g,
				"Edit",
				map[string]any{"path": "src/app.ts"},
				newWorkflowIntegrationCall("ok", nil),
				guard.WithSessionID("audit-emission-"+harness.name),
			)
			if err != nil {
				t.Fatalf("run(Edit): %v", err)
			}

			event := requireWorkflowEvent(t, sink.Events(), audit.ActionWorkflowStageAdvanced)
			if event.Action != audit.ActionWorkflowStageAdvanced {
				t.Fatalf("Action = %q, want %q", event.Action, audit.ActionWorkflowStageAdvanced)
			}
			if event.Workflow["name"] != "adapter-audit-emission" {
				t.Fatalf("workflow.name = %#v, want %q", event.Workflow["name"], "adapter-audit-emission")
			}
		})
	}
}

func workflowStateForSession(t *testing.T, rt *workflow.Runtime, backend session.StorageBackend, sessionID string) workflow.State {
	t.Helper()

	sess, err := session.New(sessionID, backend)
	if err != nil {
		t.Fatalf("session.New(%s): %v", sessionID, err)
	}
	state, err := rt.State(context.Background(), sess)
	if err != nil {
		t.Fatalf("workflow.State(%s): %v", sessionID, err)
	}
	return state
}

func mustWorkflowIntegrationRuntime(t *testing.T, doc string) *workflow.Runtime {
	t.Helper()

	def, err := workflow.LoadString(doc)
	if err != nil {
		t.Fatalf("workflow.LoadString: %v", err)
	}
	rt, err := workflow.NewRuntime(def)
	if err != nil {
		t.Fatalf("workflow.NewRuntime: %v", err)
	}
	return rt
}

func requireWorkflowEvent(t *testing.T, events []audit.Event, action audit.Action) audit.Event {
	t.Helper()

	for _, event := range events {
		if event.Action == action && event.Workflow != nil {
			return event
		}
	}
	t.Fatalf("missing workflow event %q in %+v", action, events)
	return audit.Event{}
}
