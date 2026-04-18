// Package anthropic provides an Edictum adapter for the Anthropic Go SDK.
//
// Anthropic SDK passes tool input as json.RawMessage. The adapter
// unmarshals to map[string]any for the rules pipeline, preserving the
// original RawMessage for the underlying tool function.
package anthropic

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edictum-ai/edictum-go/guard"
)

// VERSION is the adapter version.
const VERSION = "0.5.0"

// Adapter wraps a guard.Guard for use with Anthropic SDK tool functions.
type Adapter struct {
	guard *guard.Guard
	opts  []guard.RunOption
}

// New creates a new Anthropic SDK adapter.
// Any run options passed here become default guard.Run() options for
// wrapped calls. Callers can still override them via
// guard.ContextWithRunOptions.
func New(g *guard.Guard, opts ...guard.RunOption) *Adapter {
	return &Adapter{
		guard: g,
		opts:  append([]guard.RunOption(nil), opts...),
	}
}

// WrapTool wraps an Anthropic SDK Go tool function with Edictum checks.
func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, input json.RawMessage) (any, error),
) func(ctx context.Context, input json.RawMessage) (any, error) {
	return func(ctx context.Context, input json.RawMessage) (any, error) {
		ctx = guard.ContextWithDefaultRunOptions(ctx, a.opts...)
		args, err := parseRawMessage(input)
		if err != nil {
			return nil, fmt.Errorf("anthropic adapter: invalid JSON input: %w", err)
		}

		return a.guard.Run(ctx, toolName, args, func(_ map[string]any) (any, error) {
			return fn(ctx, input)
		})
	}
}

// parseRawMessage unmarshals JSON into map[string]any.
// Returns empty map for null or empty input.
func parseRawMessage(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
