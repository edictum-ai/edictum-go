package guard

import (
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/edictum-ai/edictum-go/telemetry"
)

// WithTracerProvider sets an OpenTelemetry TracerProvider for governance spans.
// Falls back to the global TracerProvider if not set, which returns no-op
// spans when no OTel SDK is configured.
// Safe to combine with WithMeterProvider — both are applied together.
// Overrides any prior WithTelemetry (last writer wins).
func WithTracerProvider(tp trace.TracerProvider) Option {
	if tp == nil {
		panic("WithTracerProvider: nil TracerProvider")
	}
	return func(g *Guard) {
		g.telemetry = nil // clear WithTelemetry if set
		g.telOpts = append(g.telOpts, telemetry.WithTracerProvider(tp))
	}
}

// WithMeterProvider sets an OpenTelemetry MeterProvider for governance
// metrics (denied/allowed counters). Falls back to the global
// MeterProvider if not set.
// Safe to combine with WithTracerProvider — both are applied together.
// Overrides any prior WithTelemetry (last writer wins).
func WithMeterProvider(mp metric.MeterProvider) Option {
	if mp == nil {
		panic("WithMeterProvider: nil MeterProvider")
	}
	return func(g *Guard) {
		g.telemetry = nil // clear WithTelemetry if set
		g.telOpts = append(g.telOpts, telemetry.WithMeterProvider(mp))
	}
}

// WithTelemetry sets a pre-configured GovernanceTelemetry instance.
// Overrides any prior WithTracerProvider/WithMeterProvider (last writer wins).
// Panics if t is nil (construction-time programmer error, consistent with
// WithMode and WithRules).
func WithTelemetry(t *telemetry.GovernanceTelemetry) Option {
	if t == nil {
		panic("WithTelemetry: nil GovernanceTelemetry")
	}
	return func(g *Guard) {
		g.telemetry = t
		g.telOpts = nil // clear provider options
	}
}
