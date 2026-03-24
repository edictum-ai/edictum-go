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
// Panics if WithTelemetry was already applied (mutually exclusive).
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(g *Guard) {
		if g.telemetry != nil {
			panic("WithTracerProvider: conflicts with WithTelemetry (use one or the other)")
		}
		g.telOpts = append(g.telOpts, telemetry.WithTracerProvider(tp))
	}
}

// WithMeterProvider sets an OpenTelemetry MeterProvider for governance
// metrics (denied/allowed counters). Falls back to the global
// MeterProvider if not set.
// Safe to combine with WithTracerProvider — both are applied together.
// Panics if WithTelemetry was already applied (mutually exclusive).
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(g *Guard) {
		if g.telemetry != nil {
			panic("WithMeterProvider: conflicts with WithTelemetry (use one or the other)")
		}
		g.telOpts = append(g.telOpts, telemetry.WithMeterProvider(mp))
	}
}

// WithTelemetry sets a pre-configured GovernanceTelemetry instance.
// Mutually exclusive with WithTracerProvider/WithMeterProvider — panics
// if provider options were already applied.
func WithTelemetry(t *telemetry.GovernanceTelemetry) Option {
	if t == nil {
		panic("WithTelemetry: nil GovernanceTelemetry")
	}
	return func(g *Guard) {
		if len(g.telOpts) > 0 {
			panic("WithTelemetry: conflicts with WithTracerProvider/WithMeterProvider (use one or the other)")
		}
		g.telemetry = t
	}
}
