package guard

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/edictum-ai/edictum-go/approval"
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
	tel := telemetry.New(telemetry.WithTracerProvider(tp))
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
}

// TestObserveMode_ApprovalSetsObservedDenySpanAttr verifies the
// observed_deny attribute when an approval contract fires in observe mode.
func TestObserveMode_ApprovalSetsObservedDenySpanAttr(t *testing.T) {
	tp := newTTP()
	tel := telemetry.New(telemetry.WithTracerProvider(tp))
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
		t.Error("expected governance.observed_deny on approval in observe mode")
	}
}

// TestApprovalTimeout_SetsSpanAttrAndAllowedCounter verifies timeout_effect=allow path.
func TestApprovalTimeout_SetsSpanAttrAndAllowedCounter(t *testing.T) {
	tp := newTTP()
	mp := newTMP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	g := New(
		WithTelemetry(tel),
		WithContracts(
			contract.Precondition{
				Name: "timeout-approval", Tool: "*", Effect: "approve",
				Timeout: 1, TimeoutEffect: "allow",
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("needs approval"), nil
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
		t.Fatalf("timeout_effect=allow should succeed: %v", err)
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

	// Verify allowed counter was incremented (timeout_effect=allow).
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

// TestApprovalTimeoutDeny_NoTimeoutAttr verifies that when
// timeout_effect is NOT "allow" (default deny), the span gets an
// error status rather than the approval_timeout attribute.
func TestApprovalTimeoutDeny_NoTimeoutAttr(t *testing.T) {
	tp := newTTP()
	tel := telemetry.New(telemetry.WithTracerProvider(tp))
	g := New(
		WithTelemetry(tel),
		WithContracts(
			contract.Precondition{
				Name: "timeout-deny", Tool: "*", Effect: "approve",
				Timeout: 1,
				Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
					return contract.Fail("needs approval"), nil
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
