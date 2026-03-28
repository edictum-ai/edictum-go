package pipeline_test

import (
	"context"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// mockProvider implements pipeline.RuleProvider for testing.
type mockProvider struct {
	limits                pipeline.OperationLimits
	hooks                 []pipeline.HookRegistration
	preconditions         []rule.Precondition
	postconditions        []rule.Postcondition
	sandboxRules          []rule.Precondition
	sessionRules          []rule.SessionRule
	observePostconditions []rule.Postcondition
	observePreconditions  []rule.Precondition
	observeSandbox        []rule.Precondition
	observeSession        []rule.SessionRule
}

func (m *mockProvider) GetLimits() pipeline.OperationLimits { return m.limits }
func (m *mockProvider) GetHooks(phase string, _ toolcall.ToolCall) []pipeline.HookRegistration {
	var out []pipeline.HookRegistration
	for _, h := range m.hooks {
		if h.Phase == phase {
			out = append(out, h)
		}
	}
	return out
}
func (m *mockProvider) GetPreconditions(env toolcall.ToolCall) []rule.Precondition {
	return filterPreconditions(m.preconditions, env)
}
func (m *mockProvider) GetPostconditions(env toolcall.ToolCall) []rule.Postcondition {
	var out []rule.Postcondition
	for _, c := range m.postconditions {
		if c.Tool == "*" || c.Tool == env.ToolName() {
			out = append(out, c)
		}
	}
	return out
}
func (m *mockProvider) GetObservePostconditions(env toolcall.ToolCall) []rule.Postcondition {
	var out []rule.Postcondition
	for _, c := range m.observePostconditions {
		if c.Tool == "*" || c.Tool == env.ToolName() {
			out = append(out, c)
		}
	}
	return out
}
func (m *mockProvider) GetSandboxRules(env toolcall.ToolCall) []rule.Precondition {
	return filterPreconditions(m.sandboxRules, env)
}
func (m *mockProvider) GetSessionRules() []rule.SessionRule {
	return m.sessionRules
}
func (m *mockProvider) GetObservePreconditions(env toolcall.ToolCall) []rule.Precondition {
	return filterPreconditions(m.observePreconditions, env)
}
func (m *mockProvider) GetObserveSandboxRules(env toolcall.ToolCall) []rule.Precondition {
	return filterPreconditions(m.observeSandbox, env)
}
func (m *mockProvider) GetObserveSessionRules() []rule.SessionRule {
	return m.observeSession
}

func filterPreconditions(pres []rule.Precondition, env toolcall.ToolCall) []rule.Precondition {
	var out []rule.Precondition
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

func makeEnvelope(t *testing.T, tool string, args map[string]any) toolcall.ToolCall {
	t.Helper()
	env, err := toolcall.CreateToolCall(context.Background(), toolcall.CreateToolCallOptions{
		ToolName: tool,
		Args:     args,
	})
	if err != nil {
		t.Fatalf("CreateToolCall: %v", err)
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
	if dec.Action != "block" {
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
		Before: func(_ context.Context, _ toolcall.ToolCall) (pipeline.HookDecision, error) {
			return pipeline.BlockHook("blocked by hook"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "hook" {
		t.Fatalf("expected hook, got %s", dec.DecisionSource)
	}
	if dec.Reason != "blocked by hook" {
		t.Fatalf("expected reason, got %q", dec.Reason)
	}
	if len(dec.HooksEvaluated) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(dec.HooksEvaluated))
	}
	if dec.HooksEvaluated[0]["result"] != "block" {
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
		Before: func(_ context.Context, _ toolcall.ToolCall) (pipeline.HookDecision, error) {
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

func TestPreExecute_PreconditionBlock(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}
	prov := defaultProvider()
	prov.preconditions = []rule.Precondition{{
		Name: "must_have_name", Tool: "*",
		Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
			if env.Args() == nil || env.Args()["name"] == nil {
				return rule.Fail("Missing required arg: name"), nil
			}
			return rule.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
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
	prov.preconditions = []rule.Precondition{{
		Name: "must_have_name", Tool: "*",
		Check: func(_ context.Context, env toolcall.ToolCall) (rule.Decision, error) {
			if env.Args() == nil || env.Args()["name"] == nil {
				return rule.Fail("Missing required arg: name"), nil
			}
			return rule.Pass(), nil
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
