// Package telemetry provides OpenTelemetry integration for Edictum governance spans and metrics.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
)

const (
	// TracerName is the instrumentation library name.
	TracerName = "edictum"
	// MeterName is the instrumentation library name for metrics.
	MeterName = "edictum"
)

// GovernanceTelemetry wraps OTel tracing and metrics for Edictum governance.
// If no TracerProvider is configured, the global provider is used, which
// returns no-op spans when no SDK is installed -- making OTel fully optional.
type GovernanceTelemetry struct {
	tracer         trace.Tracer
	deniedCounter  metric.Int64Counter
	allowedCounter metric.Int64Counter
}

// Option configures GovernanceTelemetry.
type Option func(*config)

type config struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
}

// WithTracerProvider sets a custom TracerProvider.
// If not set, otel.GetTracerProvider() (the global) is used.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *config) { c.tracerProvider = tp }
}

// WithMeterProvider sets a custom MeterProvider.
// If not set, otel.GetMeterProvider() (the global) is used.
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(c *config) { c.meterProvider = mp }
}

// New creates a GovernanceTelemetry instance. Falls back to global
// providers when none are supplied, which return no-ops if no OTel SDK
// is configured.
//
// The OTel API spec guarantees that Int64Counter always returns a valid
// (possibly no-op) instrument for well-formed names, so errors from
// counter creation are logged but not propagated — the counters degrade
// to no-ops on failure.
func New(opts ...Option) *GovernanceTelemetry {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}
	tp := cfg.tracerProvider
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	mp := cfg.meterProvider
	if mp == nil {
		mp = otel.GetMeterProvider()
	}

	tracer := tp.Tracer(TracerName)
	meter := mp.Meter(MeterName)

	// OTel API guarantees valid instruments for well-formed names.
	// Guard against buggy custom MeterProviders returning (nil, err):
	// errors are reported via otel.Handle, nil counters fall back to noop.
	noopMeter := noop.NewMeterProvider().Meter(MeterName)
	denied, err := meter.Int64Counter("edictum.calls.denied",
		metric.WithDescription("Number of denied tool calls"))
	if err != nil {
		otel.Handle(err)
	}
	if denied == nil {
		denied, _ = noopMeter.Int64Counter("edictum.calls.denied")
	}
	allowed, err := meter.Int64Counter("edictum.calls.allowed",
		metric.WithDescription("Number of allowed tool calls"))
	if err != nil {
		otel.Handle(err)
	}
	if allowed == nil {
		allowed, _ = noopMeter.Int64Counter("edictum.calls.allowed")
	}

	return &GovernanceTelemetry{
		tracer:         tracer,
		deniedCounter:  denied,
		allowedCounter: allowed,
	}
}

// Tracer returns the underlying OTel tracer.
func (t *GovernanceTelemetry) Tracer() trace.Tracer {
	return t.tracer
}

// ToolSpanAttrs returns common span attributes for a tool call.
// Accepts individual fields rather than importing envelope to avoid cycles.
func ToolSpanAttrs(toolName, sideEffect, environment, runID string, callIndex int) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("tool.name", toolName),
		attribute.String("tool.side_effect", sideEffect),
		attribute.String("governance.environment", environment),
		attribute.String("governance.run_id", runID),
		attribute.Int("tool.call_index", callIndex),
	}
}

// RecordDenial increments the denied counter.
func (t *GovernanceTelemetry) RecordDenial(ctx context.Context, toolName string) {
	t.deniedCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.String("tool.name", toolName)))
}

// RecordAllowed increments the allowed counter.
func (t *GovernanceTelemetry) RecordAllowed(ctx context.Context, toolName string) {
	t.allowedCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.String("tool.name", toolName)))
}

// SetSpanError sets the span status to ERROR with a description.
func SetSpanError(span trace.Span, reason string) {
	span.SetStatus(codes.Error, reason)
}
