package guard

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	metricembedded "go.opentelemetry.io/otel/metric/embedded"
	metricznoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	traceembedded "go.opentelemetry.io/otel/trace/embedded"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/edictum-ai/edictum-go/approval"
)

// --- test tracer infrastructure ---

type recSpan struct {
	Name       string
	Attrs      []attribute.KeyValue
	StatusCode codes.Code
	StatusDesc string
}

type tSpan struct {
	tracenoop.Span
	mu  sync.Mutex
	rec *recSpan
}

func (s *tSpan) SetStatus(c codes.Code, d string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.StatusCode = c
	s.rec.StatusDesc = d
}

func (s *tSpan) End(...trace.SpanEndOption) {}

type tTracer struct {
	traceembedded.Tracer
	mu    sync.Mutex
	spans []*recSpan
}

func (t *tTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cfg := trace.NewSpanStartConfig(opts...)
	r := &recSpan{Name: name, Attrs: cfg.Attributes()}
	t.spans = append(t.spans, r)
	sp := &tSpan{rec: r}
	return trace.ContextWithSpan(ctx, sp), sp
}

type tTP struct {
	traceembedded.TracerProvider
	tracer *tTracer
}

func newTTP() *tTP { return &tTP{tracer: &tTracer{}} }

func (p *tTP) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return p.tracer
}

// --- test meter infrastructure ---

type cRec struct {
	Name  string
	Value int64
	Attrs attribute.Set
}

type tCounter struct {
	metricembedded.Int64Counter
	mu   *sync.Mutex // shared with tMeter
	name string
	recs *[]cRec
}

func (c *tCounter) Enabled(context.Context) bool { return true }

func (c *tCounter) Add(_ context.Context, v int64, opts ...metric.AddOption) {
	cfg := metric.NewAddConfig(opts)
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.recs = append(*c.recs, cRec{Name: c.name, Value: v, Attrs: cfg.Attributes()})
}

type tMeter struct {
	metricznoop.Meter
	mu   sync.Mutex
	recs []cRec
}

func (m *tMeter) Int64Counter(name string, _ ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return &tCounter{mu: &m.mu, name: name, recs: &m.recs}, nil
}

type tMP struct {
	metricembedded.MeterProvider
	meter *tMeter
}

func newTMP() *tMP { return &tMP{meter: &tMeter{}} }

func (p *tMP) Meter(string, ...metric.MeterOption) metric.Meter {
	return p.meter
}

// --- test approval backend ---

type autoApproveBackend struct{}

func (b *autoApproveBackend) RequestApproval(_ context.Context, toolName string, _ map[string]any, msg string, _ ...approval.RequestOption) (approval.Request, error) {
	return approval.NewRequest("auto-1", toolName, nil, msg), nil
}

func (b *autoApproveBackend) PollApprovalStatus(_ context.Context, _ string) (approval.Decision, error) {
	return approval.Decision{Approved: true, Timestamp: time.Now()}, nil
}
