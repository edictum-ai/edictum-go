package guard

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/codes"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/telemetry"
)

func TestWithTracerProvider_DirectOption(t *testing.T) {
	tp := newTTP()
	g := New(WithTracerProvider(tp))

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	tp.tracer.mu.Lock()
	spans := tp.tracer.spans
	tp.tracer.mu.Unlock()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span via WithTracerProvider, got %d", len(spans))
	}
	if spans[0].Name != "edictum.governance Bash" {
		t.Errorf("span name: got %q", spans[0].Name)
	}
	if spans[0].StatusCode != codes.Ok {
		t.Errorf("expected Ok status, got %v", spans[0].StatusCode)
	}
}

func TestWithTelemetry_SpanErrorOnDeny(t *testing.T) {
	tp := newTTP()
	tel := telemetry.New(telemetry.WithTracerProvider(tp))
	deny := contract.Precondition{
		Name: "block-all",
		Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Fail("denied"), nil
		},
	}
	g := New(WithTelemetry(tel), WithContracts(deny))

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "rm"}, nopCallable)
	if err == nil {
		t.Fatal("expected denial error")
	}

	tp.tracer.mu.Lock()
	spans := tp.tracer.spans
	tp.tracer.mu.Unlock()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].StatusCode != codes.Error {
		t.Errorf("expected Error status, got %v", spans[0].StatusCode)
	}
}

func TestWithTelemetry_MetricsRecorded(t *testing.T) {
	mp := newTMP()
	tp := newTTP()
	tel := telemetry.New(
		telemetry.WithTracerProvider(tp),
		telemetry.WithMeterProvider(mp),
	)
	g := New(WithTelemetry(tel))

	_, err := g.Run(context.Background(), "Read",
		map[string]any{}, nopCallable)
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
		t.Error("expected edictum.calls.allowed counter increment")
	}
}
