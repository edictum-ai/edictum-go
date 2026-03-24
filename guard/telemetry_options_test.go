package guard

import (
	"context"
	"testing"

	"github.com/edictum-ai/edictum-go/telemetry"
)

func TestWithTelemetry_OverridesProviderOptions(t *testing.T) {
	tp1 := newTTP()
	tp2 := newTTP()
	tel := telemetry.New(telemetry.WithTracerProvider(tp2))
	// WithTelemetry after WithTracerProvider — last writer wins.
	g := New(WithTracerProvider(tp1), WithTelemetry(tel))

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	tp1.tracer.mu.Lock()
	spans1 := tp1.tracer.spans
	tp1.tracer.mu.Unlock()
	if len(spans1) != 0 {
		t.Errorf("expected 0 spans on tp1, got %d", len(spans1))
	}

	tp2.tracer.mu.Lock()
	spans2 := tp2.tracer.spans
	tp2.tracer.mu.Unlock()
	if len(spans2) != 1 {
		t.Fatalf("expected 1 span on tp2, got %d", len(spans2))
	}
}

func TestWithTracerProvider_OverridesWithTelemetry(t *testing.T) {
	tp1 := newTTP()
	tp2 := newTTP()
	tel := telemetry.New(telemetry.WithTracerProvider(tp1))
	// WithTracerProvider after WithTelemetry — last writer wins.
	g := New(WithTelemetry(tel), WithTracerProvider(tp2))

	_, err := g.Run(context.Background(), "Bash",
		map[string]any{"command": "ls"}, nopCallable)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	tp1.tracer.mu.Lock()
	spans1 := tp1.tracer.spans
	tp1.tracer.mu.Unlock()
	if len(spans1) != 0 {
		t.Errorf("expected 0 spans on tp1, got %d", len(spans1))
	}

	tp2.tracer.mu.Lock()
	spans2 := tp2.tracer.spans
	tp2.tracer.mu.Unlock()
	if len(spans2) != 1 {
		t.Fatalf("expected 1 span on tp2, got %d", len(spans2))
	}
}
