package pipeline_test

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/pipeline"
)

func TestPreExecute_ObserveModeContractDoesNotDeny(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.preconditions = []rule.Precondition{{
		Name: "observe_only", Tool: "*", Mode: "observe",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("would deny"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("observe rule should not deny, got %s", dec.Action)
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
	prov.preconditions = []rule.Precondition{{
		Name: "needs_approval", Tool: "*", Effect: "ask",
		Timeout: 60, TimeoutEffect: "allow",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("Requires human approval"), nil
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
		t.Fatalf("expected timeout_action=allow, got %s", dec.ApprovalTimeoutEff)
	}
	if dec.ApprovalMessage != "Requires human approval" {
		t.Fatalf("expected approval message, got %q", dec.ApprovalMessage)
	}
}

func TestPreExecute_ObserveContractsEvaluated(t *testing.T) {
	sess, _ := newTestSession(t)
	if _, err := sess.IncrementAttempts(context.Background()); err != nil {
		t.Fatal(err)
	}

	prov := defaultProvider()
	prov.observePreconditions = []rule.Precondition{{
		Name: "observe_check", Tool: "*",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("observe would deny"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "allow" {
		t.Fatalf("observe rules should not deny, got %s", dec.Action)
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
	prov.sandboxContracts = []rule.Precondition{{
		Name: "path_sandbox", Tool: "*", Source: "yaml_sandbox",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("path not allowed"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "Bash", map[string]any{"command": "cat /etc/shadow"})
	dec, err := p.PreExecute(context.Background(), env, sess)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "block" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.DecisionSource != "yaml_sandbox" {
		t.Fatalf("expected yaml_sandbox source, got %s", dec.DecisionSource)
	}
}
