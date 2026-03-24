package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNew_DefaultFallsBackToGlobal(t *testing.T) {
	gt := New()
	if gt == nil {
		t.Fatal("New() returned nil")
	}
	if gt.Tracer() == nil {
		t.Fatal("Tracer() returned nil")
	}
	if gt.deniedCounter == nil {
		t.Fatal("deniedCounter is nil")
	}
	if gt.allowedCounter == nil {
		t.Fatal("allowedCounter is nil")
	}
}

func TestNew_WithCustomProvider(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	gt := New(WithTracerProvider(tp))
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

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Name != "test-span" {
		t.Fatalf("expected span name %q, got %q", "test-span", spans[0].Name)
	}
}

func TestToolSpanAttrs(t *testing.T) {
	attrs := ToolSpanAttrs("Bash", "write", "production", "run-123", 5)

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

func newMetricSetup(t *testing.T) (*sdkmetric.ManualReader, *sdkmetric.MeterProvider) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	return reader, mp
}

func findCounterValue(t *testing.T, rm metricdata.ResourceMetrics, name, toolName string) int64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %q is not Sum[int64]", name)
			}
			for _, dp := range sum.DataPoints {
				for _, attr := range dp.Attributes.ToSlice() {
					if string(attr.Key) == "tool.name" && attr.Value.AsString() == toolName {
						return dp.Value
					}
				}
			}
		}
	}
	t.Fatalf("metric %q with tool.name=%q not found", name, toolName)
	return 0
}

func TestRecordDenial_IncrementsDeniedCounter(t *testing.T) {
	reader, mp := newMetricSetup(t)
	gt := New(WithMeterProvider(mp))
	ctx := context.Background()

	gt.RecordDenial(ctx, "Bash")
	gt.RecordDenial(ctx, "Bash")
	gt.RecordDenial(ctx, "FileWrite")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	bashCount := findCounterValue(t, rm, "edictum.calls.denied", "Bash")
	if bashCount != 2 {
		t.Errorf("expected Bash denied count 2, got %d", bashCount)
	}

	fwCount := findCounterValue(t, rm, "edictum.calls.denied", "FileWrite")
	if fwCount != 1 {
		t.Errorf("expected FileWrite denied count 1, got %d", fwCount)
	}
}

func TestRecordAllowed_IncrementsAllowedCounter(t *testing.T) {
	reader, mp := newMetricSetup(t)
	gt := New(WithMeterProvider(mp))
	ctx := context.Background()

	gt.RecordAllowed(ctx, "Read")
	gt.RecordAllowed(ctx, "Read")
	gt.RecordAllowed(ctx, "Read")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	count := findCounterValue(t, rm, "edictum.calls.allowed", "Read")
	if count != 3 {
		t.Errorf("expected Read allowed count 3, got %d", count)
	}
}

func TestSetSpanError_SetsErrorStatus(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	_, span := tp.Tracer("test").Start(context.Background(), "error-span")
	SetSpanError(span, "contract denied")
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Status.Code != codes.Error {
		t.Errorf("expected status code Error, got %v", s.Status.Code)
	}
	if s.Status.Description != "contract denied" {
		t.Errorf("expected status description %q, got %q", "contract denied", s.Status.Description)
	}
}

func TestSetSpanOK_SetsOKStatus(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	_, span := tp.Tracer("test").Start(context.Background(), "ok-span")
	SetSpanOK(span)
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Status.Code != codes.Ok {
		t.Errorf("expected status code Ok, got %v", s.Status.Code)
	}
}
