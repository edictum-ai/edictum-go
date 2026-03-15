package pipeline_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
)

func TestPreExecute_SessionContractDeny(t *testing.T) {
	backend := session.NewMemoryBackend()
	sess, _ := session.New("test", backend)
	ctx := context.Background()

	// Simulate 3 executions
	for i := 0; i < 3; i++ {
		if err := sess.RecordExecution(ctx, "T", true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.sessionContracts = []contract.SessionContract{{
		Name: "max_3_execs",
		Check: func(ctx context.Context, s any) (contract.Verdict, error) {
			sess := s.(*session.Session)
			count, _ := sess.ExecutionCount(ctx)
			if count >= 3 {
				return contract.Fail("Too many executions"), nil
			}
			return contract.Pass(), nil
		},
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
	if dec.DecisionSource != "session_contract" {
		t.Fatalf("expected session_contract, got %s", dec.DecisionSource)
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
	if dec.Action != "deny" {
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
	if dec.Action != "deny" {
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
		Before: func(_ context.Context, _ *envelope.ToolEnvelope) (pipeline.HookDecision, error) {
			order = append(order, "hook")
			return pipeline.AllowHook(), nil
		},
	}}
	prov.preconditions = []contract.Precondition{{
		Name: "tracking_pre", Tool: "*",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			order = append(order, "precondition")
			return contract.Pass(), nil
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
	prov.preconditions = []contract.Precondition{{
		Name: "check_a", Tool: "*",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.ContractsEvaluated) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(dec.ContractsEvaluated))
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
	prov.preconditions = []contract.Precondition{{
		Name: "bash_only", Tool: "Bash",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("bash denied"), nil
		},
	}}
	p := pipeline.New(prov)

	// Non-Bash tool should not be affected
	readEnv := makeEnvelope(t, "Read", map[string]any{"file_path": "/tmp/x"})
	dec, err := p.PreExecute(ctx, readEnv, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("Read should be allowed, got %s", dec.Action)
	}

	// Bash tool should be denied
	bashEnv := makeEnvelope(t, "Bash", map[string]any{"command": "ls"})
	dec, err = p.PreExecute(ctx, bashEnv, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
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
		Before: func(_ context.Context, _ *envelope.ToolEnvelope) (pipeline.HookDecision, error) {
			return pipeline.HookDecision{}, errors.New("hook exploded")
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
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
	prov.preconditions = []contract.Precondition{{
		Name: "exploding", Tool: "*",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Verdict{}, errors.New("check exploded")
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
	if !dec.PolicyError {
		t.Fatal("expected policy_error=true")
	}
}

func TestPreExecute_ObserveModeContractDoesNotDeny(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []contract.Precondition{{
		Name: "observe_only", Tool: "*", Mode: "observe",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("would deny"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("observe contract should not deny, got %s", dec.Action)
	}
	if !dec.Observed {
		t.Fatal("expected Observed=true")
	}
}

func TestPreExecute_ApprovalPending(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []contract.Precondition{{
		Name: "needs_approval", Tool: "*", Effect: "approve",
		Timeout: 60, TimeoutEffect: "allow",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("Requires human approval"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "pending_approval" {
		t.Fatalf("expected pending_approval, got %s", dec.Action)
	}
	if dec.ApprovalTimeout != 60 {
		t.Fatalf("expected timeout=60, got %d", dec.ApprovalTimeout)
	}
	if dec.ApprovalTimeoutEff != "allow" {
		t.Fatalf("expected timeout_effect=allow, got %s", dec.ApprovalTimeoutEff)
	}
	if dec.ApprovalMessage != "Requires human approval" {
		t.Fatalf("expected approval message, got %q", dec.ApprovalMessage)
	}
}

func TestPreExecute_DenialsCountAsAttempts(t *testing.T) {
	backend := session.NewMemoryBackend()
	sess, _ := session.New("test", backend)
	ctx := context.Background()

	// 2 attempts, limit is 3 — first call denied by precondition,
	// second call should still work (not hit attempt limit yet)
	prov := &mockProvider{limits: pipeline.OperationLimits{
		MaxAttempts: 3, MaxToolCalls: 200, MaxCallsPerTool: map[string]int{},
	}}
	prov.preconditions = []contract.Precondition{{
		Name: "always_deny", Tool: "*",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("denied"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)

	// Each pre_execute is preceded by increment_attempts in the runner
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	dec, err := p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}

	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	dec, err = p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}

	if _, err := sess.IncrementAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	dec, err = p.PreExecute(ctx, env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "attempt_limit" {
		t.Fatalf("3rd attempt should hit attempt_limit, got %s", dec.DecisionSource)
	}
}

func TestPreExecute_ObserveContractsEvaluated(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.observePreconditions = []contract.Precondition{{
		Name: "observe_check", Tool: "*",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("observe would deny"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("observe contracts should not deny, got %s", dec.Action)
	}
	if len(dec.ObserveResults) != 1 {
		t.Fatalf("expected 1 observe result, got %d", len(dec.ObserveResults))
	}
	if dec.ObserveResults[0]["passed"] != false {
		t.Fatal("expected observe result passed=false")
	}
}

func TestPreExecute_SandboxContractDeny(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.sandboxContracts = []contract.Precondition{{
		Name: "path_sandbox", Tool: "*", Source: "yaml_sandbox",
		Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("path not allowed"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "Bash", map[string]any{"command": "cat /etc/shadow"})
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "yaml_sandbox" {
		t.Fatalf("expected yaml_sandbox source, got %s", dec.DecisionSource)
	}
}

func TestPreExecute_PolicyErrorAggregation(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []contract.Precondition{
		{
			Name: "error_contract", Tool: "*",
			Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
				return contract.Fail("err", map[string]any{"policy_error": true}), nil
			},
		},
		{
			Name: "pass_contract", Tool: "*",
			Check: func(_ context.Context, _ *envelope.ToolEnvelope) (contract.Verdict, error) {
				return contract.Pass(), nil
			},
		},
	}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	// First contract fails -> deny
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if !dec.PolicyError {
		t.Fatal("expected policy_error=true (aggregated)")
	}
}

// --- Parity IDs ---
func TestParity_1_22_MessageTruncation500(t *testing.T) {
	long := strings.Repeat("x", 600)
	v := contract.Fail(long)
	if len(v.Message()) != 500 {
		t.Fatalf("expected 500, got %d", len(v.Message()))
	}
	if !strings.HasSuffix(v.Message(), "...") {
		t.Fatal("expected ... suffix")
	}
}

func TestParity_1_23_PreDecisionShape(t *testing.T) {
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

	// Verify all fields are present and have correct zero-value types
	_ = dec.Action
	_ = dec.Reason
	_ = dec.DecisionSource
	_ = dec.DecisionName
	_ = dec.HooksEvaluated
	_ = dec.ContractsEvaluated
	_ = dec.Observed
	_ = dec.PolicyError
	_ = dec.ObserveResults
	_ = dec.ApprovalTimeout
	_ = dec.ApprovalTimeoutEff
	_ = dec.ApprovalMessage

	if dec.HooksEvaluated == nil {
		t.Fatal("HooksEvaluated should be non-nil slice")
	}
	if dec.ContractsEvaluated == nil {
		t.Fatal("ContractsEvaluated should be non-nil slice")
	}
}

func TestParity_1_5_HookExceptionDeny(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.hooks = []pipeline.HookRegistration{{
		Phase: "before", Tool: "*", Name: "boom",
		Before: func(_ context.Context, _ *envelope.ToolEnvelope) (pipeline.HookDecision, error) {
			return pipeline.HookDecision{}, fmt.Errorf("kaboom")
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "deny" {
		t.Fatalf("hook exception should deny, got %s", dec.Action)
	}
	if !strings.Contains(dec.Reason, "Hook error:") {
		t.Fatalf("expected 'Hook error:' in reason, got %q", dec.Reason)
	}
}
