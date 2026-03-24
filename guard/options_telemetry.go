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
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(g *Guard) {
		g.telOpts = append(g.telOpts, telemetry.WithTracerProvider(tp))
	}
}

// WithMeterProvider sets an OpenTelemetry MeterProvider for governance
// metrics (denied/allowed counters). Falls back to the global
// MeterProvider if not set.
// Safe to combine with WithTracerProvider — both are applied together.
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(g *Guard) {
		g.telOpts = append(g.telOpts, telemetry.WithMeterProvider(mp))
	}
}

// WithTelemetry sets a pre-configured GovernanceTelemetry instance.
// Overrides any WithTracerProvider/WithMeterProvider options regardless
// of ordering — accumulated provider options are cleared.
func WithTelemetry(t *telemetry.GovernanceTelemetry) Option {
	return func(g *Guard) {
		g.telemetry = t
		g.telOpts = nil
	}
}
