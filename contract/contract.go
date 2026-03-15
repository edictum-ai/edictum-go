// Package contract defines the core contract types for edictum governance.
package contract

import (
	"context"

	"github.com/edictum-ai/edictum-go/envelope"
)

// Verdict represents the outcome of a contract check.
type Verdict struct {
	passed   bool
	message  string
	metadata map[string]any
}

// Passed returns whether the verdict allows the tool call.
func (v Verdict) Passed() bool { return v.passed }

// Message returns the verdict message (max 500 chars).
func (v Verdict) Message() string { return v.message }

// Metadata returns the verdict metadata.
func (v Verdict) Metadata() map[string]any { return v.metadata }

// Pass creates a passing verdict.
func Pass() Verdict {
	return Verdict{passed: true}
}

// Fail creates a failing verdict with a message (truncated to 500 chars).
func Fail(message string, metadata ...map[string]any) Verdict {
	if len(message) > 500 {
		message = message[:500]
	}
	var meta map[string]any
	if len(metadata) > 0 {
		meta = metadata[0]
	}
	return Verdict{passed: false, message: message, metadata: meta}
}

// Precondition defines a check that runs before tool execution.
type Precondition struct {
	Tool  string
	Check func(ctx context.Context, env envelope.ToolEnvelope) (Verdict, error)
	When  func(ctx context.Context, env envelope.ToolEnvelope) bool
}

// Postcondition defines a check that runs after tool execution.
type Postcondition struct {
	Tool  string
	Check func(ctx context.Context, env envelope.ToolEnvelope, response any) (Verdict, error)
	When  func(ctx context.Context, env envelope.ToolEnvelope) bool
}

// SessionContract defines a check that evaluates session-level state.
type SessionContract struct {
	Check func(ctx context.Context, session any) (Verdict, error)
}
