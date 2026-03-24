package guard

import (
	"fmt"

	"go.opentelemetry.io/otel/trace"

	"github.com/edictum-ai/edictum-go/telemetry"
)

// WithTracerProvider sets an OpenTelemetry TracerProvider for governance spans.
// Falls back to the global TracerProvider if not set, which returns no-op
// spans when no OTel SDK is configured.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(g *Guard) {
		t, err := telemetry.New(telemetry.WithTracerProvider(tp))
		if err != nil {
			panic(fmt.Sprintf("telemetry init: %v", err))
		}
		g.telemetry = t
	}
}

// WithTelemetry sets a pre-configured GovernanceTelemetry instance.
func WithTelemetry(t *telemetry.GovernanceTelemetry) Option {
	return func(g *Guard) { g.telemetry = t }
}
