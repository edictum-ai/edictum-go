package guard

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/telemetry"
)

// hasSpanAttr reports whether the recorded spans contain the given
// boolean attribute key set to true.
func hasSpanAttr(spans []*recSpan, key string) bool {
	for _, s := range spans {
		for _, kv := range s.Attrs {
			if string(kv.Key) == key && kv.Value.AsBool() {
				return true
			}
		}
	}
	return false
}

// TestObserveMode_SetsObservedDenySpanAttr verifies that
// governance.observed_deny is set on the span when a deny fires in
// observe mode.
func TestObserveMode_SetsObservedDenySpanAttr(t *testing.T) {
	tp := newTTP()
	mp := newTMP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	g := New(
		WithMode("observe"),
		WithTelemetry(tel),
		WithContracts(
			contract.Precondition{
				Name: "deny-all",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("denied by contract"), nil
				},
			},
		),
	)

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("observe mode should not error: %v", err)
	}

	tp.tracer.mu.Lock()
	spans := tp.tracer.spans
	tp.tracer.mu.Unlock()

	if !hasSpanAttr(spans, "governance.observed_deny") {
		t.Error("expected governance.observed_deny attribute on span")
	}
	mp.meter.mu.Lock()
	recs := mp.meter.recs
	mp.meter.mu.Unlock()
	deniedFound := false
	for _, r := range recs {
		if r.Name == "edictum.calls.denied" {
			deniedFound = true
			break
		}
	}
	if !deniedFound {
		t.Error("expected edictum.calls.denied in observe mode")
	}
}

// TestObserveMode_ApprovalDoesNotSetObservedDenySpanAttr verifies that
// observe mode does not treat pending approval as an observed deny.
func TestObserveMode_ApprovalDoesNotSetObservedDenySpanAttr(t *testing.T) {
	tp := newTTP()
	mp := newTMP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	g := New(
		WithMode("observe"),
		WithTelemetry(tel),
		WithContracts(
			contract.Precondition{
				Name:   "approval-contract",
				Effect: "approve",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("needs approval"), nil
				},
			},
		),
		WithApprovalBackend(&autoApproveBackend{}),
	)

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("approval in observe mode should still succeed after approval: %v", err)
	}

	tp.tracer.mu.Lock()
	spans := tp.tracer.spans
	tp.tracer.mu.Unlock()

	if hasSpanAttr(spans, "governance.observed_deny") {
		t.Error("did not expect governance.observed_deny on approval in observe mode")
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
		t.Error("expected edictum.calls.allowed for approval in observe mode")
	}
}
