// Package adkgo provides an edictum adapter for Google ADK Go.
//
// This adapter wraps an edictum Guard as Google ADK callbacks without
// importing the actual ADK Go package. Users wire the callbacks manually
// into their ADK agent configuration, keeping edictum-go zero-dep.
package adkgo

import (
	"context"
	"errors"
	"fmt"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/guard"
)

// VERSION is the adapter version.
const VERSION = "0.1.0"

// BeforeToolCallback is the signature matching google.golang.org/adk's
// BeforeToolCallback. Returns non-nil map to skip tool execution (deny).
type BeforeToolCallback func(
	ctx context.Context,
	toolName string,
	args map[string]any,
) (map[string]any, error)

// AfterToolCallback is the signature matching ADK's AfterToolCallback.
// Can replace the tool result.
type AfterToolCallback func(
	ctx context.Context,
	toolName string,
	args map[string]any,
	result map[string]any,
	err error,
) (map[string]any, error)

// Adapter wraps an edictum Guard for Google ADK Go.
type Adapter struct {
	guard *guard.Guard
}

// New creates an ADK Go adapter for the given guard.
func New(g *guard.Guard) *Adapter {
	return &Adapter{guard: g}
}

// Callbacks returns (BeforeToolCallback, AfterToolCallback) for ADK
// agent config. The before callback denies by returning a non-nil map
// with an "error" key. The after callback is a no-op passthrough since
// postconditions are handled inside guard.Run().
func (a *Adapter) Callbacks() (BeforeToolCallback, AfterToolCallback) {
	before := func(
		ctx context.Context,
		toolName string,
		args map[string]any,
	) (map[string]any, error) {
		// Run a no-op callable through the guard. If the guard denies,
		// we return a deny map. Otherwise we return nil (allow).
		_, err := a.guard.Run(ctx, toolName, args,
			func(_ map[string]any) (any, error) { return nil, nil })
		if err != nil {
			var denied *edictum.DeniedError
			if errors.As(err, &denied) {
				return map[string]any{
					"error": fmt.Sprintf("DENIED: %s", denied.Reason),
				}, nil
			}
			return nil, err
		}
		return nil, nil
	}

	after := func(
		_ context.Context,
		_ string,
		_ map[string]any,
		result map[string]any,
		_ error,
	) (map[string]any, error) {
		// Postconditions already ran inside guard.Run() in the before
		// callback. The after callback is a passthrough.
		return result, nil
	}

	return before, after
}

// WrapTool wraps a tool function with governance enforcement.
// This is the simplest integration path -- the adapter calls guard.Run()
// with the tool callable, running the full governance pipeline.
func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, args map[string]any) (any, error),
) func(ctx context.Context, args map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) {
		return a.guard.Run(ctx, toolName, args,
			func(a map[string]any) (any, error) {
				return fn(ctx, a)
			})
	}
}
