package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/edictum-ai/edictum-go/adapter/adkgo"
	"github.com/edictum-ai/edictum-go/adapter/eino"
	"github.com/edictum-ai/edictum-go/adapter/genkit"
	"github.com/edictum-ai/edictum-go/adapter/langchaingo"
	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/workflow"
)

type adapterHarness struct {
	name string
	run  func(context.Context, *guard.Guard, workflowAdapterStep, *stepExecutor) (any, error)
}

func adapterHarnesses() []adapterHarness {
	return []adapterHarness{
		{name: "adkgo", run: runADKStep},
		{name: "eino", run: runEinoStep},
		{name: "genkit", run: runGenkitStep},
		{name: "langchaingo", run: runLangChainGoStep},
	}
}

func runADKStep(ctx context.Context, g *guard.Guard, step workflowAdapterStep, executor *stepExecutor) (any, error) {
	wrapped := adkgo.New(g).WrapTool(step.Call.Tool, executor.adkCallable())
	return wrapped(ctx, step.Call.Args)
}

func runLangChainGoStep(ctx context.Context, g *guard.Guard, step workflowAdapterStep, executor *stepExecutor) (any, error) {
	input, err := json.Marshal(step.Call.Args)
	if err != nil {
		return nil, err
	}
	wrapped := langchaingo.New(g).WrapTool(step.Call.Tool, executor.langChainCallable())
	return wrapped(ctx, string(input))
}

func runEinoStep(ctx context.Context, g *guard.Guard, step workflowAdapterStep, executor *stepExecutor) (any, error) {
	wrapped := eino.New(g).WrapTool(step.Call.Tool, executor.adkCallable())
	return wrapped(ctx, step.Call.Args)
}

func runGenkitStep(ctx context.Context, g *guard.Guard, step workflowAdapterStep, executor *stepExecutor) (any, error) {
	wrapped := genkit.New(g).WrapTool(step.Call.Tool, executor.adkCallable())
	return wrapped(ctx, step.Call.Args)
}

type stepExecutor struct {
	execution string
	called    bool
}

func newStepExecutor(execution string) *stepExecutor {
	return &stepExecutor{execution: execution}
}

func (e *stepExecutor) adkCallable() func(context.Context, map[string]any) (any, error) {
	return func(_ context.Context, _ map[string]any) (any, error) {
		return e.result()
	}
}

func (e *stepExecutor) langChainCallable() func(context.Context, string) (string, error) {
	return func(_ context.Context, _ string) (string, error) {
		result, err := e.result()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%v", result), nil
	}
}

func (e *stepExecutor) result() (any, error) {
	e.called = true
	switch e.execution {
	case "success":
		return "ok", nil
	case "error":
		return nil, errors.New("fixture tool failure")
	case "not_run":
		return nil, errors.New("tool executed unexpectedly")
	default:
		return nil, fmt.Errorf("unsupported execution mode %q", e.execution)
	}
}

func (e *stepExecutor) Assert(t *testing.T, fixtureID, stepID string) {
	t.Helper()
	if e.execution == "not_run" && e.called {
		t.Fatalf("%s/%s executed unexpectedly", fixtureID, stepID)
	}
	if e.execution != "not_run" && !e.called {
		t.Fatalf("%s/%s did not execute", fixtureID, stepID)
	}
}

type queuedApprovalBackend struct {
	mu       sync.Mutex
	outcomes []string
	nextID   int
}

func newQueuedApprovalBackend() *queuedApprovalBackend {
	return &queuedApprovalBackend{}
}

func (b *queuedApprovalBackend) SetOutcomes(outcomes []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.outcomes = append([]string{}, outcomes...)
}

func (b *queuedApprovalBackend) RequestApproval(_ context.Context, toolName string, toolArgs map[string]any, message string, opts ...approval.RequestOption) (approval.Request, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	return approval.NewRequest(fmt.Sprintf("fixture-approval-%d", b.nextID), toolName, toolArgs, message, opts...), nil
}

func (b *queuedApprovalBackend) PollApprovalStatus(_ context.Context, _ string) (approval.Decision, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.outcomes) == 0 {
		return approval.Decision{}, errors.New("approval requested without queued outcome")
	}

	outcome := b.outcomes[0]
	b.outcomes = b.outcomes[1:]
	decision := approval.Decision{Timestamp: time.Now().UTC()}
	switch outcome {
	case "approved":
		decision.Approved = true
		decision.Status = approval.StatusApproved
	case "rejected":
		decision.Status = approval.StatusDenied
	default:
		return approval.Decision{}, fmt.Errorf("unsupported approval outcome %q", outcome)
	}
	return decision, nil
}

func (b *queuedApprovalBackend) AssertDrained(t *testing.T, fixtureID, stepID string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.outcomes) != 0 {
		t.Fatalf("%s/%s approval outcomes left unused: %+v", fixtureID, stepID, b.outcomes)
	}
}

func seedWorkflowState(t *testing.T, backend session.StorageBackend, def workflow.Definition, state workflow.State) {
	t.Helper()

	sess, err := session.New(state.SessionID, backend)
	if err != nil {
		t.Fatalf("session.New(%s): %v", state.SessionID, err)
	}
	stateCopy := state
	if stateCopy.Approvals == nil {
		stateCopy.Approvals = map[string]string{}
	}
	if stateCopy.CompletedStages == nil {
		stateCopy.CompletedStages = []string{}
	}
	if stateCopy.Evidence.Reads == nil {
		stateCopy.Evidence.Reads = []string{}
	}
	if stateCopy.Evidence.StageCalls == nil {
		stateCopy.Evidence.StageCalls = map[string][]string{}
	}
	raw, err := json.Marshal(stateCopy)
	if err != nil {
		t.Fatalf("Marshal seeded state: %v", err)
	}
	key := "workflow:" + def.Metadata.Name + ":state"
	if err := sess.SetValue(context.Background(), key, string(raw)); err != nil {
		t.Fatalf("SetValue(%s): %v", key, err)
	}
}
