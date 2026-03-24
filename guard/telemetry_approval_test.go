package guard

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/telemetry"
)

func TestApprovalGranted_RecordsAllowedCounter(t *testing.T) {
	mp := newTMP()
	tp := newTTP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	pre := contract.Precondition{
		Name:   "needs-approval",
		Effect: "approve",
		Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("needs approval"), nil
		},
	}
	g := New(
		WithTelemetry(tel),
		WithContracts(pre),
		WithApprovalBackend(&autoApproveBackend{}),
	)

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	mp.meter.mu.Lock()
	recs := mp.meter.recs
	mp.meter.mu.Unlock()
	found := false
	for _, r := range recs {
		if r.Name == "edictum.calls.allowed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected edictum.calls.allowed after approval granted")
	}
}

func TestApprovalNilBackend_RecordsDenialCounter(t *testing.T) {
	mp := newTMP()
	tp := newTTP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	pre := contract.Precondition{
		Name:   "needs-approval",
		Effect: "approve",
		Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("needs approval"), nil
		},
	}
	// No approval backend — should deny immediately.
	g := New(
		WithTelemetry(tel),
		WithContracts(pre),
	)

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err == nil {
		t.Fatal("expected denial error when no approval backend configured")
	}

	mp.meter.mu.Lock()
	recs := mp.meter.recs
	mp.meter.mu.Unlock()
	found := false
	for _, r := range recs {
		if r.Name == "edictum.calls.denied" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected edictum.calls.denied when approval backend is nil")
	}
}

func TestApprovalDenied_RecordsDenialCounter(t *testing.T) {
	mp := newTMP()
	tp := newTTP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	pre := contract.Precondition{
		Name:   "needs-approval",
		Effect: "approve",
		Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("needs approval"), nil
		},
	}
	g := New(
		WithTelemetry(tel),
		WithContracts(pre),
		WithApprovalBackend(&autoDenyBackend{}),
	)

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "rm"}, nopCallable)
	if err == nil {
		t.Fatal("expected denial error")
	}

	mp.meter.mu.Lock()
	recs := mp.meter.recs
	mp.meter.mu.Unlock()
	found := false
	for _, r := range recs {
		if r.Name == "edictum.calls.denied" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected edictum.calls.denied after approval denied")
	}
}
