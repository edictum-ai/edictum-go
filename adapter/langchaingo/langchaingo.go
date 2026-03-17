// Package langchaingo provides an edictum adapter for LangChainGo.
//
// LangChainGo tools take a string input and return a string result.
// The adapter parses input as JSON into map[string]any when possible,
// falling back to {"input": rawString} for non-JSON input.
// On deny, returns an error wrapping edictum.DeniedError.
package langchaingo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edictum-ai/edictum-go/guard"
)

// VERSION is the adapter version.
const VERSION = "0.1.0"

// Adapter wraps a guard.Guard for use with LangChainGo tool functions.
type Adapter struct {
	guard *guard.Guard
}

// New creates a new LangChainGo adapter.
func New(g *guard.Guard) *Adapter {
	return &Adapter{guard: g}
}

// WrapTool wraps a LangChainGo tool function with governance.
// On deny, returns an error wrapping edictum.DeniedError.
func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, input string) (string, error),
) func(ctx context.Context, input string) (string, error) {
	return func(ctx context.Context, input string) (string, error) {
		args := parseInput(input)

		result, err := a.guard.Run(ctx, toolName, args, func(_ map[string]any) (any, error) {
			return fn(ctx, input)
		})
		if err != nil {
			return "", err
		}

		if result == nil {
			return "", nil
		}
		s, ok := result.(string)
		if !ok {
			return fmt.Sprintf("%v", result), nil
		}
		return s, nil
	}
}

// parseInput tries to parse input as JSON map. Falls back to {"input": input}.
func parseInput(input string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(input), &m); err == nil {
		return m
	}
	return map[string]any{"input": input}
}
