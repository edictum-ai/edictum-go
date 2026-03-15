package pipeline_test

import (
	"context"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
)

// mockProvider implements pipeline.ContractProvider for testing.
type mockProvider struct {
	limits                pipeline.OperationLimits
	hooks                 []pipeline.HookRegistration
	preconditions         []contract.Precondition
	postconditions        []contract.Postcondition
	sandboxContracts      []contract.Precondition
	sessionContracts      []contract.SessionContract
	observePostconditions []contract.Postcondition
	observePreconditions  []contract.Precondition
	observeSandbox        []contract.Precondition
	observeSession        []contract.SessionContract
}

func (m *mockProvider) GetLimits() pipeline.OperationLimits { return m.limits }
func (m *mockProvider) GetHooks(phase string, _ envelope.ToolEnvelope) []pipeline.HookRegistration {
	var out []pipeline.HookRegistration
	for _, h := range m.hooks {
		if h.Phase == phase {
			out = append(out, h)
		}
	}
	return out
}
func (m *mockProvider) GetPreconditions(env envelope.ToolEnvelope) []contract.Precondition {
	return filterPreconditions(m.preconditions, env)
}
func (m *mockProvider) GetPostconditions(env envelope.ToolEnvelope) []contract.Postcondition {
	var out []contract.Postcondition
	for _, c := range m.postconditions {
		if c.Tool == "*" || c.Tool == env.ToolName() {
			out = append(out, c)
		}
	}
	return out
}
func (m *mockProvider) GetObservePostconditions(env envelope.ToolEnvelope) []contract.Postcondition {
	var out []contract.Postcondition
	for _, c := range m.observePostconditions {
		if c.Tool == "*" || c.Tool == env.ToolName() {
			out = append(out, c)
		}
	}
	return out
}
func (m *mockProvider) GetSandboxContracts(env envelope.ToolEnvelope) []contract.Precondition {
	return filterPreconditions(m.sandboxContracts, env)
}
func (m *mockProvider) GetSessionContracts() []contract.SessionContract {
	return m.sessionContracts
}
func (m *mockProvider) GetObservePreconditions(env envelope.ToolEnvelope) []contract.Precondition {
	return filterPreconditions(m.observePreconditions, env)
}
func (m *mockProvider) GetObserveSandboxContracts(env envelope.ToolEnvelope) []contract.Precondition {
	return filterPreconditions(m.observeSandbox, env)
}
func (m *mockProvider) GetObserveSessionContracts() []contract.SessionContract {
	return m.observeSession
}

func filterPreconditions(pres []contract.Precondition, env envelope.ToolEnvelope) []contract.Precondition {
	var out []contract.Precondition
	for _, c := range pres {
		if c.Tool == "*" || c.Tool == env.ToolName() {
			out = append(out, c)
		}
	}
	return out
}

func newTestSession(t *testing.T) (*session.Session, *session.MemoryBackend) {
	t.Helper()
	backend := session.NewMemoryBackend()
	sess, err := session.New("pipeline-test", backend)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	return sess, backend
}

func makeEnvelope(t *testing.T, tool string, args map[string]any) envelope.ToolEnvelope {
	t.Helper()
	env, err := envelope.CreateEnvelope(context.Background(), envelope.CreateEnvelopeOptions{
		ToolName: tool,
		Args:     args,
	})
	if err != nil {
		t.Fatalf("CreateEnvelope: %v", err)
	}
	return env
}

func defaultProvider() *mockProvider {
	return &mockProvider{limits: pipeline.DefaultLimits()}
}

// --- PreExecute tests (parity 1.1–1.12) ---

func TestPreExecute_AllowWithNoContracts(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(defaultProvider())
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
	if dec.Reason != "" {
		t.Fatalf("expected empty reason, got %q", dec.Reason)
	}
}

func TestPreExecute_AttemptLimitDeny(t *testing.T) {
	backend := session.NewMemoryBackend()
	sess, _ := session.New("test", backend)
	ctx := context.Background()
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}

	prov := &mockProvider{limits: pipeline.OperationLimits{
		MaxAttempts: 2, MaxToolCalls: 200, MaxCallsPerTool: map[string]int{},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "attempt_limit" {
		t.Fatalf("expected attempt_limit, got %s", dec.DecisionSource)
	}
	if !strings.Contains(strings.ToLower(dec.Reason), "retry loop") {
		t.Fatalf("expected reason with 'retry loop', got %q", dec.Reason)
	}
}

func TestPreExecute_HookDeny(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}
	prov := defaultProvider()
	prov.hooks = []pipeline.HookRegistration{{
		Phase: "before", Tool: "*", Name: "deny_all",
		Before: func(_ context.Context, _ envelope.ToolEnvelope) (pipeline.HookDecision, error) {
			return pipeline.DenyHook("denied by hook"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "hook" {
		t.Fatalf("expected hook, got %s", dec.DecisionSource)
	}
	if dec.Reason != "denied by hook" {
		t.Fatalf("expected reason, got %q", dec.Reason)
	}
	if len(dec.HooksEvaluated) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(dec.HooksEvaluated))
	}
	if dec.HooksEvaluated[0]["result"] != "deny" {
		t.Fatalf("expected deny result in hook record")
	}
}

func TestPreExecute_HookAllowContinues(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}
	prov := defaultProvider()
	prov.hooks = []pipeline.HookRegistration{{
		Phase: "before", Tool: "*", Name: "allow_all",
		Before: func(_ context.Context, _ envelope.ToolEnvelope) (pipeline.HookDecision, error) {
			return pipeline.AllowHook(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
	if len(dec.HooksEvaluated) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(dec.HooksEvaluated))
	}
}

func TestPreExecute_PreconditionDeny(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}
	prov := defaultProvider()
	prov.preconditions = []contract.Precondition{{
		Name: "must_have_name", Tool: "*",
		Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
			if env.Args() == nil || env.Args()["name"] == nil {
				return contract.Fail("Missing required arg: name"), nil
			}
			return contract.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "precondition" {
		t.Fatalf("expected precondition, got %s", dec.DecisionSource)
	}
	if !strings.Contains(dec.Reason, "name") {
		t.Fatalf("expected reason with 'name', got %q", dec.Reason)
	}
}

func TestPreExecute_PreconditionPass(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}
	prov := defaultProvider()
	prov.preconditions = []contract.Precondition{{
		Name: "must_have_name", Tool: "*",
		Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
			if env.Args() == nil || env.Args()["name"] == nil {
				return contract.Fail("Missing required arg: name"), nil
			}
			return contract.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", map[string]any{"name": "test"})
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
}
