package pipeline_test

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
)

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
