package telemetry_test

import (
	"context"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	metricembedded "go.opentelemetry.io/otel/metric/embedded"
	metricznoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	traceembedded "go.opentelemetry.io/otel/trace/embedded"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// recordedSpan captures span data for test assertions.
type recordedSpan struct {
	Name       string
	Attrs      []attribute.KeyValue
	StatusCode codes.Code
	StatusDesc string
	ended      bool
}

// testSpan implements trace.Span for recording span operations.
type testSpan struct {
	tracenoop.Span
	mu       sync.Mutex
	recorded *recordedSpan
}

func (s *testSpan) SetStatus(code codes.Code, desc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded.StatusCode = code
	s.recorded.StatusDesc = desc
}

func (s *testSpan) End(...trace.SpanEndOption) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded.ended = true
}

// testTracer records span creation.
type testTracer struct {
	traceembedded.Tracer
	mu    sync.Mutex
	spans []*recordedSpan
}

func (t *testTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cfg := trace.NewSpanStartConfig(opts...)
	rec := &recordedSpan{Name: name, Attrs: cfg.Attributes()}
	t.spans = append(t.spans, rec)
	span := &testSpan{recorded: rec}
	return trace.ContextWithSpan(ctx, span), span
}

func (t *testTracer) getSpans() []*recordedSpan {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]*recordedSpan, len(t.spans))
	copy(cp, t.spans)
	return cp
}

// testTracerProvider returns the test tracer.
type testTracerProvider struct {
	traceembedded.TracerProvider
	tracer *testTracer
}

func newTestTracerProvider() *testTracerProvider {
	return &testTracerProvider{tracer: &testTracer{}}
}

func (p *testTracerProvider) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return p.tracer
}

// counterRecord stores a single Add call.
type counterRecord struct {
	Name  string
	Value int64
	Attrs attribute.Set
}

// testCounter records Add calls.
type testCounter struct {
	metricembedded.Int64Counter
	mu      sync.Mutex
	name    string
	records *[]counterRecord
}

func (c *testCounter) Enabled(context.Context) bool { return true }

func (c *testCounter) Add(_ context.Context, val int64, opts ...metric.AddOption) {
	cfg := metric.NewAddConfig(opts)
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.records = append(*c.records, counterRecord{
		Name:  c.name,
		Value: val,
		Attrs: cfg.Attributes(),
	})
}

// testMeter creates test counters; delegates everything else to noop.
type testMeter struct {
	metricznoop.Meter
	mu      sync.Mutex
	records []counterRecord
}

func (m *testMeter) Int64Counter(name string, _ ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return &testCounter{name: name, records: &m.records}, nil
}

func (m *testMeter) getRecords() []counterRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]counterRecord, len(m.records))
	copy(cp, m.records)
	return cp
}

// testMeterProvider returns the test meter.
type testMeterProvider struct {
	metricembedded.MeterProvider
	meter *testMeter
}

func newTestMeterProvider() *testMeterProvider {
	return &testMeterProvider{meter: &testMeter{}}
}

func (p *testMeterProvider) Meter(string, ...metric.MeterOption) metric.Meter {
	return p.meter
}

// findCounterSum sums counter values for a given name and tool.name.
func findCounterSum(t *testing.T, records []counterRecord, counterName, toolName string) int64 {
	t.Helper()
	var sum int64
	found := false
	for _, r := range records {
		if r.Name != counterName {
			continue
		}
		for _, kv := range r.Attrs.ToSlice() {
			if string(kv.Key) == "tool.name" && kv.Value.AsString() == toolName {
				sum += r.Value
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("counter %q with tool.name=%q not found", counterName, toolName)
	}
	return sum
}
