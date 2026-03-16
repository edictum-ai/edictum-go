package guard

import (
	"context"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/redaction"
	"github.com/edictum-ai/edictum-go/session"
)

// 7.1: Constructor with 15 params
func TestNewGuardAllParams(t *testing.T) {
	backend := session.NewMemoryBackend()
	sink := &audit.StdoutSink{}
	pol := redaction.NewPolicy()
	principal := envelope.NewPrincipal(envelope.WithUserID("user-1"))
	limits := pipeline.OperationLimits{
		MaxAttempts:     100,
		MaxToolCalls:    50,
		MaxCallsPerTool: map[string]int{"Bash": 10},
	}

	denyCalled := false
	allowCalled := false
	postWarnCalled := false
	var approvalBe approval.Backend

	g := New(
		WithEnvironment("staging"),
		WithMode("observe"),
		WithLimits(limits),
		WithContracts(
			contract.Precondition{Name: "pre1", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Pass(), nil
				}},
			contract.Postcondition{Name: "post1", Tool: "*",
				Check: func(_ context.Context, _ envelope.ToolEnvelope, _ any) (contract.Verdict, error) {
					return contract.Pass(), nil
				}},
			contract.SessionContract{Name: "sess1",
				Check: func(_ context.Context, _ any) (contract.Verdict, error) {
					return contract.Pass(), nil
				}},
		),
		WithHooks(pipeline.HookRegistration{Phase: "before", Tool: "*", Name: "h1",
			Before: func(_ context.Context, _ envelope.ToolEnvelope) (pipeline.HookDecision, error) {
				return pipeline.AllowHook(), nil
			}}),
		WithAuditSink(sink),
		WithRedaction(pol),
		WithBackend(backend),
		WithPolicyVersion("v1.0"),
		WithOnDeny(func(_ envelope.ToolEnvelope, _ string, _ string) { denyCalled = true }),
		WithOnAllow(func(_ envelope.ToolEnvelope) { allowCalled = true }),
		WithOnPostWarn(func(_ envelope.ToolEnvelope, _ []string) { postWarnCalled = true }),
		WithSuccessCheck(func(_ string, _ any) bool { return true }),
		WithPrincipal(&principal),
		WithPrincipalResolver(func(_ string, _ map[string]any) *envelope.Principal { return nil }),
		WithApprovalBackend(approvalBe),
		WithTools(map[string]map[string]any{
			"ReadFile": {"side_effect": "read", "idempotent": true},
		}),
	)

	if g.environment != "staging" {
		t.Errorf("environment: got %q, want %q", g.environment, "staging")
	}
	if g.Mode() != "observe" {
		t.Errorf("mode: got %q, want %q", g.Mode(), "observe")
	}
	if g.Limits().MaxAttempts != 100 {
		t.Errorf("max_attempts: got %d, want 100", g.Limits().MaxAttempts)
	}
	if g.PolicyVersion() != "v1.0" {
		t.Errorf("policy_version: got %q, want %q", g.PolicyVersion(), "v1.0")
	}
	if g.LocalSink() == nil {
		t.Error("local_sink should not be nil")
	}
	if len(g.state.preconditions) != 1 {
		t.Errorf("preconditions: got %d, want 1", len(g.state.preconditions))
	}
	if len(g.state.postconditions) != 1 {
		t.Errorf("postconditions: got %d, want 1", len(g.state.postconditions))
	}
	if len(g.state.sessionContracts) != 1 {
		t.Errorf("session_contracts: got %d, want 1", len(g.state.sessionContracts))
	}
	if len(g.beforeHooks) != 1 {
		t.Errorf("before_hooks: got %d, want 1", len(g.beforeHooks))
	}

	// Verify callbacks are set (not called yet)
	_ = denyCalled
	_ = allowCalled
	_ = postWarnCalled
}

func TestNewGuardDefaults(t *testing.T) {
	g := New()
	if g.environment != "production" {
		t.Errorf("default environment: got %q, want %q", g.environment, "production")
	}
	if g.mode != "enforce" {
		t.Errorf("default mode: got %q, want %q", g.mode, "enforce")
	}
	if g.Limits().MaxAttempts != 500 {
		t.Errorf("default max_attempts: got %d, want 500", g.Limits().MaxAttempts)
	}
	if g.Limits().MaxToolCalls != 200 {
		t.Errorf("default max_tool_calls: got %d, want 200", g.Limits().MaxToolCalls)
	}
	if g.sessionID == "" {
		t.Error("sessionID should be generated")
	}
	if g.LocalSink() == nil {
		t.Error("local_sink should always be present")
	}
}

// 7.15: SetPrincipal
func TestSetPrincipal(t *testing.T) {
	g := New()
	p := envelope.NewPrincipal(envelope.WithUserID("u-new"))
	g.SetPrincipal(&p)
	if g.principal == nil || g.principal.UserID() != "u-new" {
		t.Error("SetPrincipal did not update")
	}
}

// 7.16: Tool registry from dict
func TestToolRegistryFromDict(t *testing.T) {
	g := New(WithTools(map[string]map[string]any{
		"ReadFile":  {"side_effect": "read", "idempotent": true},
		"WriteFile": {"side_effect": "write"},
	}))

	se, idem := g.toolRegistry.Classify("ReadFile")
	if se != envelope.SideEffectRead {
		t.Errorf("ReadFile side_effect: got %q, want %q", se, envelope.SideEffectRead)
	}
	if !idem {
		t.Error("ReadFile idempotent: got false, want true")
	}

	se2, idem2 := g.toolRegistry.Classify("WriteFile")
	if se2 != envelope.SideEffectWrite {
		t.Errorf("WriteFile side_effect: got %q, want %q", se2, envelope.SideEffectWrite)
	}
	if idem2 {
		t.Error("WriteFile idempotent: got true, want false")
	}
}

func TestGenerateUUID(t *testing.T) {
	id := generateUUID()
	if len(id) != 36 {
		t.Errorf("UUID length: got %d, want 36", len(id))
	}
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Errorf("UUID format invalid: %s", id)
	}
	// Version 4: char at position 14 should be '4'
	if id[14] != '4' {
		t.Errorf("UUID version: got %c, want '4'", id[14])
	}
	// Uniqueness
	id2 := generateUUID()
	if id == id2 {
		t.Error("two UUIDs should not be equal")
	}
}

// 7.14: Principal resolver overrides static principal
func TestPrincipalResolverOverridesStatic(t *testing.T) {
	static := envelope.NewPrincipal(envelope.WithUserID("static"))
	resolved := envelope.NewPrincipal(envelope.WithUserID("resolved"))

	g := New(
		WithPrincipal(&static),
		WithPrincipalResolver(func(_ string, _ map[string]any) *envelope.Principal {
			return &resolved
		}),
	)

	got := g.resolvePrincipal("Bash", nil)
	if got == nil || got.UserID() != "resolved" {
		t.Error("resolver should override static principal")
	}
}

func TestPrincipalStaticFallback(t *testing.T) {
	static := envelope.NewPrincipal(envelope.WithUserID("static"))
	g := New(WithPrincipal(&static))

	got := g.resolvePrincipal("Bash", nil)
	if got == nil || got.UserID() != "static" {
		t.Error("should fall back to static principal")
	}
}

func TestContractProviderInterface(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "pre1", Tool: "Bash",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Pass(), nil
				}},
			contract.Precondition{Name: "pre2", Tool: "Read",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Pass(), nil
				}},
		),
	)

	ctx := context.Background()
	bashEnv, _ := envelope.CreateEnvelope(ctx, envelope.CreateEnvelopeOptions{
		ToolName: "Bash",
		Args:     map[string]any{"command": "ls"},
	})

	pres := g.GetPreconditions(bashEnv)
	if len(pres) != 1 || pres[0].Name != "pre1" {
		t.Errorf("GetPreconditions: got %d, want 1 matching Bash", len(pres))
	}

	readEnv, _ := envelope.CreateEnvelope(ctx, envelope.CreateEnvelopeOptions{
		ToolName: "Read",
	})
	pres2 := g.GetPreconditions(readEnv)
	if len(pres2) != 1 || pres2[0].Name != "pre2" {
		t.Errorf("GetPreconditions(Read): got %d, want 1", len(pres2))
	}
}

func TestObserveContracts(t *testing.T) {
	g := New(
		WithContracts(
			contract.Precondition{Name: "observe-pre", Tool: "*", Mode: "observe",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("observed"), nil
				}},
		),
	)

	if len(g.state.preconditions) != 0 {
		t.Error("observe contract should not be in enforce list")
	}
	if len(g.state.observePreconditions) != 1 {
		t.Error("observe contract should be in observe list")
	}

	ctx := context.Background()
	env2, _ := envelope.CreateEnvelope(ctx, envelope.CreateEnvelopeOptions{
		ToolName: "Bash",
	})
	obs := g.GetObservePreconditions(env2)
	if len(obs) != 1 || obs[0].Name != "observe-pre" {
		t.Error("GetObservePreconditions should return observe contracts")
	}
}

func TestGlobToolMatching(t *testing.T) {
	cases := []struct {
		pattern string
		tool    string
		want    bool
	}{
		{"*", "Bash", true},
		{"", "Bash", true},
		{"Bash", "Bash", true},
		{"Bash", "Read", false},
		{"Bash*", "BashExec", true},
		{"Read*", "Bash", false},
	}
	for _, tc := range cases {
		got := toolMatches(tc.pattern, tc.tool)
		if got != tc.want {
			t.Errorf("toolMatches(%q, %q): got %v, want %v",
				tc.pattern, tc.tool, got, tc.want)
		}
	}
}

func TestAuditSinkWithLocalSink(t *testing.T) {
	g := New()
	// Default: audit sink IS the local sink
	ctx := context.Background()
	event := audit.NewEvent()
	event.ToolName = "test"
	event.Action = audit.ActionCallAllowed
	if err := g.auditSink.Emit(ctx, &event); err != nil {
		t.Fatal(err)
	}
	events := g.LocalSink().Events()
	if len(events) != 1 {
		t.Errorf("events: got %d, want 1", len(events))
	}
}

func TestAuditSinkComposite(t *testing.T) {
	extra := audit.NewCollectingSink(100)
	g := New(WithAuditSink(extra))

	ctx := context.Background()
	event := audit.NewEvent()
	event.ToolName = "test"
	event.Action = audit.ActionCallDenied
	if err := g.auditSink.Emit(ctx, &event); err != nil {
		t.Fatal(err)
	}

	// Both sinks should receive the event
	if len(g.LocalSink().Events()) != 1 {
		t.Error("local sink should have 1 event")
	}
	if len(extra.Events()) != 1 {
		t.Error("extra sink should have 1 event")
	}
}

func TestDefaultSuccessCheck(t *testing.T) {
	cases := []struct {
		name   string
		result any
		want   bool
	}{
		{"nil", nil, true},
		{"string ok", "hello", true},
		{"error prefix", "Error: bad", false},
		{"fatal prefix", "fatal: fail", false},
		{"FATAL prefix", "Fatal: fail", false},
		{"error with case", "ERROR: bad", false},
		{"map no error", map[string]any{"data": 1}, true},
		{"map is_error true", map[string]any{"is_error": true}, false},
		{"map is_error false", map[string]any{"is_error": false}, true},
		{"int", 42, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := defaultSuccessCheck("tool", tc.result)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilterHooksGlob(t *testing.T) {
	hooks := []pipeline.HookRegistration{
		{Phase: "before", Tool: "Bash", Name: "bash-hook"},
		{Phase: "before", Tool: "*", Name: "all-hook"},
		{Phase: "before", Tool: "Read*", Name: "read-hook"},
	}
	ctx := context.Background()
	env2, _ := envelope.CreateEnvelope(ctx, envelope.CreateEnvelopeOptions{
		ToolName: "Bash",
	})

	got := filterHooks(hooks, env2)
	if len(got) != 2 {
		t.Errorf("got %d hooks, want 2 (bash-hook, all-hook)", len(got))
	}
	names := make([]string, len(got))
	for i, h := range got {
		names[i] = h.Name
	}
	joined := strings.Join(names, ",")
	if joined != "bash-hook,all-hook" {
		t.Errorf("hook names: got %q", joined)
	}
}
