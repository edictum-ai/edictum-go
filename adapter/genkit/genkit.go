// Package genkit provides an edictum adapter for Firebase Genkit Go.
//
// Genkit tools use map[string]any for arguments and return any,
// similar to Eino. The adapter wraps the tool function with guard.Run().
package genkit

import (
	"context"

	"github.com/edictum-ai/edictum-go/guard"
)

// VERSION is the adapter version.
const VERSION = "0.3.0"

// Adapter wraps a guard.Guard for use with Genkit tool functions.
type Adapter struct {
	guard *guard.Guard
	opts  []guard.RunOption
}

// New creates a new Genkit adapter.
// Any run options passed here are forwarded on every guard.Run() call
// and take precedence over options carried in ctx via
// guard.ContextWithRunOptions.
func New(g *guard.Guard, opts ...guard.RunOption) *Adapter {
	return &Adapter{
		guard: g,
		opts:  append([]guard.RunOption(nil), opts...),
	}
}

// WrapTool wraps a Genkit tool function with governance.
func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, args map[string]any) (any, error),
) func(ctx context.Context, args map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) {
		return a.guard.Run(ctx, toolName, args, func(m map[string]any) (any, error) {
			return fn(ctx, m)
		}, a.opts...)
	}
}
