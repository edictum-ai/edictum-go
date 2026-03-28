package telemetry_test

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/edictum-ai/edictum-go/telemetry"
)

func TestNew_DefaultFallsBackToGlobal(t *testing.T) {
	gt := telemetry.New()
	if gt == nil {
		t.Fatal("New() returned nil")
	}
	if gt.Tracer() == nil {
		t.Fatal("Tracer() returned nil")
	}
	// Verify counters work via public API (no panic).
	gt.RecordDenial(context.Background(), "test")
	gt.RecordAllowed(context.Background(), "test")
}

func TestNew_WithCustomProvider(t *testing.T) {
	tp := newTestTracerProvider()

	gt := telemetry.New(telemetry.WithTracerProvider(tp))
	if gt == nil {
		t.Fatal("New() returned nil")
	}

	tracer := gt.Tracer()
	if tracer == nil {
		t.Fatal("Tracer() returned nil with custom provider")
	}

	// Start a span to verify it goes through the custom provider.
	ctx, span := tracer.Start(context.Background(), "test-span")
	_ = ctx
	span.End()

	spans := tp.tracer.getSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Name != "test-span" {
		t.Fatalf("expected span name %q, got %q", "test-span", spans[0].Name)
	}
}

func TestToolSpanAttrs(t *testing.T) {
	attrs := telemetry.ToolSpanAttrs("Bash", "write", "production", "run-123", 5)

	expected := []attribute.KeyValue{
		attribute.String("tool.name", "Bash"),
		attribute.String("tool.side_effect", "write"),
		attribute.String("governance.environment", "production"),
		attribute.String("governance.run_id", "run-123"),
		attribute.Int("tool.call_index", 5),
	}

	if len(attrs) != len(expected) {
		t.Fatalf("expected %d attributes, got %d", len(expected), len(attrs))
	}
	for i, want := range expected {
		got := attrs[i]
		if got.Key != want.Key {
			t.Errorf("attr[%d]: expected key %q, got %q", i, want.Key, got.Key)
		}
		if got.Value != want.Value {
			t.Errorf("attr[%d] (%s): expected value %v, got %v", i, want.Key, want.Value, got.Value)
		}
	}
}

func TestRecordDenial_IncrementsDeniedCounter(t *testing.T) {
	mp := newTestMeterProvider()
	gt := telemetry.New(telemetry.WithMeterProvider(mp))
	ctx := context.Background()

	gt.RecordDenial(ctx, "Bash")
	gt.RecordDenial(ctx, "Bash")
	gt.RecordDenial(ctx, "FileWrite")

	records := mp.meter.getRecords()
	bashCount := findCounterSum(t, records, "edictum.calls.denied", "Bash")
	if bashCount != 2 {
		t.Errorf("expected Bash denied count 2, got %d", bashCount)
	}

	fwCount := findCounterSum(t, records, "edictum.calls.denied", "FileWrite")
	if fwCount != 1 {
		t.Errorf("expected FileWrite denied count 1, got %d", fwCount)
	}
}

func TestRecordAllowed_IncrementsAllowedCounter(t *testing.T) {
	mp := newTestMeterProvider()
	gt := telemetry.New(telemetry.WithMeterProvider(mp))
	ctx := context.Background()

	gt.RecordAllowed(ctx, "Read")
	gt.RecordAllowed(ctx, "Read")
	gt.RecordAllowed(ctx, "Read")

	records := mp.meter.getRecords()
	count := findCounterSum(t, records, "edictum.calls.allowed", "Read")
	if count != 3 {
		t.Errorf("expected Read allowed count 3, got %d", count)
	}
}

func TestSetSpanError_SetsErrorStatus(t *testing.T) {
	tp := newTestTracerProvider()
	_, span := tp.tracer.Start(context.Background(), "error-span")
	telemetry.SetSpanError(span, "rule denied")
	span.End()

	spans := tp.tracer.getSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.StatusCode != codes.Error {
		t.Errorf("expected status code Error, got %v", s.StatusCode)
	}
	if s.StatusDesc != "rule denied" {
		t.Errorf("expected status description %q, got %q", "rule denied", s.StatusDesc)
	}
}

func TestSetSpanError_ViaSpanFromContext(t *testing.T) {
	tp := newTestTracerProvider()
	ctx, span := tp.tracer.Start(context.Background(), "ctx-span")

	// Retrieve span from context (mirrors how guard code works).
	retrieved := trace.SpanFromContext(ctx)
	telemetry.SetSpanError(retrieved, "timeout")
	span.End()

	spans := tp.tracer.getSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].StatusCode != codes.Error {
		t.Errorf("expected Error, got %v", spans[0].StatusCode)
	}
}
