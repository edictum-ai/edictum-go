package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/edictum-ai/edictum-go/adapter/adkgo"
	adapteranthropic "github.com/edictum-ai/edictum-go/adapter/anthropic"
	"github.com/edictum-ai/edictum-go/adapter/eino"
	"github.com/edictum-ai/edictum-go/adapter/genkit"
	"github.com/edictum-ai/edictum-go/adapter/langchaingo"
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
		{name: "anthropic", run: runAnthropicIntegration},
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

func (c *workflowIntegrationCall) anthropicCallable() func(context.Context, json.RawMessage) (any, error) {
	return func(_ context.Context, _ json.RawMessage) (any, error) {
		c.called.Store(true)
		return c.result, c.err
	}
}

func runADKIntegration(ctx context.Context, g *guard.Guard, toolName string, args map[string]any, call *workflowIntegrationCall, opts ...guard.RunOption) (any, error) {
	return adkgo.New(g, opts...).WrapTool(toolName, call.mapCallable())(ctx, args)
}

func runAnthropicIntegration(ctx context.Context, g *guard.Guard, toolName string, args map[string]any, call *workflowIntegrationCall, opts ...guard.RunOption) (any, error) {
	input, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return adapteranthropic.New(g, opts...).WrapTool(toolName, call.anthropicCallable())(ctx, input)
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
