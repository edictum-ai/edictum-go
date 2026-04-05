// Package eino provides an edictum adapter for Eino (CloudWeGo).
//
// Eino tools use map[string]any for arguments and return any.
// This is the simplest adapter since the signature matches guard.Run().
package eino

import (
	"context"

	"github.com/edictum-ai/edictum-go/guard"
)

// VERSION is the adapter version.
const VERSION = "0.4.0"

// Adapter wraps a guard.Guard for use with Eino tool functions.
type Adapter struct {
	guard *guard.Guard
	opts  []guard.RunOption
}

// New creates a new Eino adapter.
// Any run options passed here become default guard.Run() options for
// wrapped calls. Callers can still override them via
// guard.ContextWithRunOptions.
func New(g *guard.Guard, opts ...guard.RunOption) *Adapter {
	return &Adapter{
		guard: g,
		opts:  append([]guard.RunOption(nil), opts...),
	}
}

// WrapTool wraps an Eino tool function with governance.
func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, args map[string]any) (any, error),
) func(ctx context.Context, args map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) {
		ctx = guard.ContextWithDefaultRunOptions(ctx, a.opts...)
		return a.guard.Run(ctx, toolName, args, func(m map[string]any) (any, error) {
			return fn(ctx, m)
		})
	}
}
