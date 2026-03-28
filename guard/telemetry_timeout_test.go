package guard

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/telemetry"
)

// TestApprovalTimeout_SetsSpanAttrAndAllowedCounter verifies timeout_action=allow path.
func TestApprovalTimeout_SetsSpanAttrAndAllowedCounter(t *testing.T) {
	tp := newTTP()
	mp := newTMP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	g := New(
		WithTelemetry(tel),
		WithRules(
			rule.Precondition{
				Name: "timeout-approval", Tool: "*", Effect: "ask",
				Timeout: 1, TimeoutEffect: "allow",
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("needs approval"), nil
				},
			},
		),
		WithApprovalBackend(&blockingApprovalBackend{}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"},
		func(_ map[string]any) (any, error) { return "ok", nil })
	if err != nil {
		t.Fatalf("timeout_action=allow should succeed: %v", err)
	}

	tp.tracer.mu.Lock()
	spans := tp.tracer.spans
	tp.tracer.mu.Unlock()

	found := false
	for _, s := range spans {
		for _, kv := range s.Attrs {
			if string(kv.Key) == "governance.approval_timeout" &&
				kv.Value.Type() == attribute.BOOL && kv.Value.AsBool() {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected governance.approval_timeout attribute on span")
	}

	mp.meter.mu.Lock()
	recs := mp.meter.recs
	mp.meter.mu.Unlock()
	allowedFound := false
	for _, r := range recs {
		if r.Name == "edictum.calls.allowed" {
			allowedFound = true
			break
		}
	}
	if !allowedFound {
		t.Error("expected edictum.calls.allowed on approval timeout-allow")
	}
}

// TestApprovalTimeoutDeny_NoTimeoutAttr verifies that timeout_action=deny
// sets span error status rather than the approval_timeout attribute.
func TestApprovalTimeoutDeny_NoTimeoutAttr(t *testing.T) {
	tp := newTTP()
	tel := telemetry.New(telemetry.WithTracerProvider(tp))
	g := New(
		WithTelemetry(tel),
		WithRules(
			rule.Precondition{
				Name: "timeout-deny", Tool: "*", Effect: "ask",
				Timeout: 1,
				Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
					return rule.Fail("needs approval"), nil
				},
			},
		),
		WithApprovalBackend(&blockingApprovalBackend{}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := g.Run(ctx, "Bash", map[string]any{"command": "ls"}, nopCallable)
	if err == nil {
		t.Fatal("expected denial on timeout with default effect")
	}

	tp.tracer.mu.Lock()
	spans := tp.tracer.spans
	tp.tracer.mu.Unlock()

	if hasSpanAttr(spans, "governance.approval_timeout") {
		t.Error("approval_timeout attr should NOT be set for deny path")
	}
}

// Verify blockingApprovalBackend implements approval.Backend.
var _ approval.Backend = (*blockingApprovalBackend)(nil)
