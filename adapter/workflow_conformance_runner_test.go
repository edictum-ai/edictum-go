package adapter

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/workflow"
	yamlv3 "gopkg.in/yaml.v3"
)

func TestWorkflowAdapterConformanceFixtures(t *testing.T) {
	suites := loadWorkflowAdapterSuites(t)

	for _, harness := range adapterHarnesses() {
		t.Run(harness.name, func(t *testing.T) {
			for _, loaded := range suites {
				loaded := loaded
				t.Run(filepath.Base(loaded.path), func(t *testing.T) {
					runtimes := buildWorkflowRuntimes(t, loaded.suite.Workflows)

					for _, fixture := range loaded.suite.Fixtures {
						fixture := fixture
						t.Run(fixture.ID, func(t *testing.T) {
							rt := runtimes[fixture.Workflow]
							backend := session.NewMemoryBackend()
							approvals := newQueuedApprovalBackend()
							g := guard.New(
								guard.WithBackend(backend),
								guard.WithWorkflowRuntime(rt),
								guard.WithApprovalBackend(approvals),
							)
							seedWorkflowState(t, backend, rt.Definition(), fixture.InitialState)

							for _, step := range fixture.Steps {
								step := step
								approvals.SetOutcomes(step.ApprovalOutcomes)
								mark := g.LocalSink().Mark()
								ctx := guard.ContextWithRunOptions(
									context.Background(),
									guard.WithSessionID(fixture.InitialState.SessionID),
								)
								if fixture.Lineage.ParentSessionID != "" {
									ctx = guard.ContextWithRunOptions(ctx, guard.WithParentSessionID(fixture.Lineage.ParentSessionID))
								}

								executor := newStepExecutor(step.Execution)
								_, err := harness.run(ctx, g, step, executor)
								assertStepOutcome(t, fixture.ID, step, err)
								executor.Assert(t, fixture.ID, step.ID)
								approvals.AssertDrained(t, fixture.ID, step.ID)

								events, err := g.LocalSink().SinceMark(mark)
								if err != nil {
									t.Fatalf("%s/%s SinceMark: %v", fixture.ID, step.ID, err)
								}
								assertAuditEvents(t, fixture.ID, step.ID, events, step.Expect.AuditEvents)

								sess, err := session.New(fixture.InitialState.SessionID, backend)
								if err != nil {
									t.Fatalf("%s/%s session.New: %v", fixture.ID, step.ID, err)
								}
								state, err := rt.State(context.Background(), sess)
								if err != nil {
									t.Fatalf("%s/%s State: %v", fixture.ID, step.ID, err)
								}
								assertWorkflowState(t, fixture.ID, step.ID, state, step.Expect)
							}
						})
					}
				})
			}
		})
	}
}

func buildWorkflowRuntimes(t *testing.T, docs map[string]any) map[string]*workflow.Runtime {
	t.Helper()

	runtimes := make(map[string]*workflow.Runtime, len(docs))
	for name, doc := range docs {
		raw, err := yamlv3.Marshal(doc)
		if err != nil {
			t.Fatalf("Marshal workflow %s: %v", name, err)
		}
		def, err := workflow.LoadString(string(raw))
		if err != nil {
			t.Fatalf("LoadString(%s): %v", name, err)
		}
		rt, err := workflow.NewRuntime(def)
		if err != nil {
			t.Fatalf("NewRuntime(%s): %v", name, err)
		}
		runtimes[name] = rt
	}
	return runtimes
}
