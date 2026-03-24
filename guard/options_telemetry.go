package guard

import (
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/edictum-ai/edictum-go/telemetry"
)

// WithTracerProvider sets an OpenTelemetry TracerProvider for governance spans.
// Falls back to the global TracerProvider if not set, which returns no-op
// spans when no OTel SDK is configured.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(g *Guard) {
		g.telemetry = telemetry.New(telemetry.WithTracerProvider(tp))
	}
}

// WithMeterProvider sets an OpenTelemetry MeterProvider for governance
// metrics (denied/allowed counters). Falls back to the global
// MeterProvider if not set.
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(g *Guard) {
		g.telemetry = telemetry.New(telemetry.WithMeterProvider(mp))
	}
}

// WithTelemetry sets a pre-configured GovernanceTelemetry instance.
// Use this when you need both a custom TracerProvider and MeterProvider.
func WithTelemetry(t *telemetry.GovernanceTelemetry) Option {
	return func(g *Guard) { g.telemetry = t }
}
