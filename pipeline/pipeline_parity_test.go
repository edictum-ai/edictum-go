package pipeline_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
)

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
