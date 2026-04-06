// Package adkgo provides an Edictum adapter for Google ADK Go.
//
// This adapter wraps an Edictum Guard without importing the actual ADK Go
// package. Users wire the wrapped tools into their ADK agent
// configuration, keeping edictum-go zero-dep.
//
// Integration: use WrapTool() to wrap any tool function with the full
// rules pipeline (pre-execute -> execute -> post-execute -> audit).
package adkgo

import (
	"context"

	"github.com/edictum-ai/edictum-go/guard"
)

// VERSION is the adapter version.
const VERSION = "0.4.0"

// Adapter wraps an edictum Guard for Google ADK Go.
type Adapter struct {
	guard *guard.Guard
	opts  []guard.RunOption
}

// New creates an ADK Go adapter for the given guard.
// Any run options passed here become default guard.Run() options for
// wrapped calls. Callers can still override them via
// guard.ContextWithRunOptions.
func New(g *guard.Guard, opts ...guard.RunOption) *Adapter {
	return &Adapter{
		guard: g,
		opts:  append([]guard.RunOption(nil), opts...),
	}
}

// WrapTool wraps a tool function with rule and workflow enforcement.
// The adapter calls guard.Run() with the tool callable, running the
// full rules pipeline: pre-execute checks, tool execution,
// post-execute checks, and audit emission.
//
// On deny, returns an *edictum.BlockedError. On tool failure, returns
// an *edictum.ToolError. Otherwise returns the tool result (possibly
// redacted by postconditions).
func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, args map[string]any) (any, error),
) func(ctx context.Context, args map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) {
		ctx = guard.ContextWithDefaultRunOptions(ctx, a.opts...)
		return a.guard.Run(ctx, toolName, args,
			func(m map[string]any) (any, error) {
				return fn(ctx, m)
			})
	}
}
