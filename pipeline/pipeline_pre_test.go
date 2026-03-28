package pipeline_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
)

func TestPreExecute_SessionRuleDeny(t *testing.T) {
	backend := session.NewMemoryBackend()
	sess, _ := session.New("test", backend)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := sess.RecordExecution(ctx, "T", true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.sessionContracts = []rule.SessionRule{{
		Name: "max_3_execs",
		Check: func(ctx context.Context, s any) (rule.Decision, error) {
			sess := s.(*session.Session)
			count, _ := sess.ExecutionCount(ctx)
			if count >= 3 {
				return rule.Fail("Too many executions"), nil
			}
			return rule.Pass(), nil
		},
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
	if dec.DecisionSource != "session_rule" {
		t.Fatalf("expected session_rule, got %s", dec.DecisionSource)
	}
}

func TestPreExecute_ExecutionLimitDeny(t *testing.T) {
	backend := session.NewMemoryBackend()
	sess, _ := session.New("test", backend)
	ctx := context.Background()

	if err := sess.RecordExecution(ctx, "T", true); err != nil {
		t.Fatal(err)
	}
	if err := sess.RecordExecution(ctx, "T", true); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}

	prov := &mockProvider{limits: pipeline.OperationLimits{
		MaxAttempts: 500, MaxToolCalls: 2, MaxCallsPerTool: map[string]int{},
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
	if dec.DecisionSource != "operation_limit" {
		t.Fatalf("expected operation_limit, got %s", dec.DecisionSource)
	}
	if dec.DecisionName != "max_tool_calls" {
		t.Fatalf("expected max_tool_calls, got %s", dec.DecisionName)
	}
}

func TestPreExecute_PerToolLimitDeny(t *testing.T) {
	backend := session.NewMemoryBackend()
	sess, _ := session.New("test", backend)
	ctx := context.Background()

	if err := sess.RecordExecution(ctx, "Bash", true); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}

	prov := &mockProvider{limits: pipeline.OperationLimits{
		MaxAttempts: 500, MaxToolCalls: 200,
		MaxCallsPerTool: map[string]int{"Bash": 1},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "Bash", map[string]any{"command": "ls"})
	dec, err := p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if !strings.Contains(strings.ToLower(dec.Reason), "per-tool limit") {
		t.Fatalf("expected per-tool limit reason, got %q", dec.Reason)
	}
}

func TestPreExecute_EvaluationOrder(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	var order []string
	prov := defaultProvider()
	prov.hooks = []pipeline.HookRegistration{{
		Phase: "before", Tool: "*", Name: "tracking_hook",
		Before: func(_ context.Context, _ toolcall.ToolCall) (pipeline.HookDecision, error) {
			order = append(order, "hook")
			return pipeline.AllowHook(), nil
		},
	}}
	prov.preconditions = []rule.Precondition{{
		Name: "tracking_pre", Tool: "*",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			order = append(order, "precondition")
			return rule.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	_, _ = p.PreExecute(context.Background(), env, sess)

	if len(order) != 2 || order[0] != "hook" || order[1] != "precondition" {
		t.Fatalf("expected [hook, precondition], got %v", order)
	}
}

func TestPreExecute_ContractsEvaluatedPopulated(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []rule.Precondition{{
		Name: "check_a", Tool: "*",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.ContractsEvaluated) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(dec.ContractsEvaluated))
	}
	if dec.ContractsEvaluated[0]["type"] != "precondition" {
		t.Fatalf("expected precondition type, got %v", dec.ContractsEvaluated[0]["type"])
	}
	if dec.ContractsEvaluated[0]["passed"] != true {
		t.Fatalf("expected passed=true")
	}
}

func TestPreExecute_ToolSpecificPrecondition(t *testing.T) {
	sess, _ := newTestSession(t)
	ctx := context.Background()
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []rule.Precondition{{
		Name: "bash_only", Tool: "Bash",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("bash denied"), nil
		},
	}}
	p := pipeline.New(prov)

	readEnv := makeEnvelope(t, "Read", map[string]any{"file_path": "/tmp/x"})
	dec, err := p.PreExecute(ctx, readEnv, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("Read should be allowed, got %s", dec.Action)
	}

	bashEnv := makeEnvelope(t, "Bash", map[string]any{"command": "ls"})
	dec, err = p.PreExecute(ctx, bashEnv, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("Bash should be denied, got %s", dec.Action)
	}
}

func TestPreExecute_HookExceptionDenies(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.hooks = []pipeline.HookRegistration{{
		Phase: "before", Tool: "*", Name: "exploding_hook",
		Before: func(_ context.Context, _ toolcall.ToolCall) (pipeline.HookDecision, error) {
			return pipeline.HookDecision{}, errors.New("hook exploded")
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny on hook error, got %s", dec.Action)
	}
	if !dec.PolicyError {
		t.Fatal("expected policy_error=true on hook exception")
	}
}

func TestPreExecute_PreconditionExceptionDenies(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []rule.Precondition{{
		Name: "exploding", Tool: "*",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Decision{}, errors.New("check exploded")
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
	if !dec.PolicyError {
		t.Fatal("expected policy_error=true")
	}
}

func TestPreExecute_DenialsCountAsAttempts(t *testing.T) {
	backend := session.NewMemoryBackend()
	sess, _ := session.New("test", backend)
	ctx := context.Background()

	prov := &mockProvider{limits: pipeline.OperationLimits{
		MaxAttempts: 3, MaxToolCalls: 200, MaxCallsPerTool: map[string]int{},
	}}
	prov.preconditions = []rule.Precondition{{
		Name: "always_deny", Tool: "*",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("denied"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)

	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	dec, err := p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}

	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	dec, err = p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}

	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	dec, err = p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "attempt_limit" {
		t.Fatalf("3rd attempt should hit attempt_limit, got %s", dec.DecisionSource)
	}
}

func TestPreExecute_PolicyErrorAggregation(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []rule.Precondition{
		{
			Name: "error_contract", Tool: "*",
			Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
				return rule.Fail("err", map[string]any{"policy_error": true}), nil
			},
		},
		{
			Name: "pass_contract", Tool: "*",
			Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
				return rule.Pass(), nil
			},
		},
	}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if !dec.PolicyError {
		t.Fatal("expected policy_error=true (aggregated)")
	}
}
