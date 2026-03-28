package guard

import (
	"context"
	"testing"
	"time"

	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/telemetry"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func TestApprovalGranted_RecordsAllowedCounter(t *testing.T) {
	mp := newTMP()
	tp := newTTP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	pre := rule.Precondition{
		Name:   "needs-approval",
		Effect: "ask",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("needs approval"), nil
		},
	}
	g := New(
		WithTelemetry(tel),
		WithRules(pre),
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
	pre := rule.Precondition{
		Name:   "needs-approval",
		Effect: "ask",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("needs approval"), nil
		},
	}
	// No approval backend — should deny immediately.
	g := New(
		WithTelemetry(tel),
		WithRules(pre),
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
	pre := rule.Precondition{
		Name:   "needs-approval",
		Effect: "ask",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("needs approval"), nil
		},
	}
	g := New(
		WithTelemetry(tel),
		WithRules(pre),
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

func TestApprovalTimeoutDeny_RecordsDenialCounter(t *testing.T) {
	mp := newTMP()
	tp := newTTP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	pre := rule.Precondition{
		Name:          "needs-approval",
		Effect:        "ask",
		Timeout:       1,
		TimeoutEffect: "block",
		Check: func(_ context.Context, _ toolcall.ToolCall) (rule.Decision, error) {
			return rule.Fail("needs approval"), nil
		},
	}
	g := New(
		WithTelemetry(tel),
		WithRules(pre),
		WithApprovalBackend(&blockingApprovalBackend{}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := g.Run(ctx, "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err == nil {
		t.Fatal("expected denial error on approval timeout")
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
		t.Error("expected edictum.calls.denied on approval timeout-deny")
	}
}
