// Package rule defines the core rule types for edictum governance.
package rule

import (
	"context"
	"regexp"

	"github.com/edictum-ai/edictum-go/toolcall"
)

// Decision represents the outcome of a rule check.
type Decision struct {
	passed   bool
	message  string
	metadata map[string]any
}

// Passed returns whether the decision allows the tool call.
func (v Decision) Passed() bool { return v.passed }

// Message returns the decision message (max 500 chars).
func (v Decision) Message() string { return v.message }

// Metadata returns the decision metadata.
func (v Decision) Metadata() map[string]any { return v.metadata }

// Pass creates a passing decision.
func Pass() Decision {
	return Decision{passed: true}
}

// Fail creates a failing decision with a message (truncated to 500 chars).
// Truncation preserves readability: "xxx..." (497 chars + "...").
func Fail(message string, metadata ...map[string]any) Decision {
	if len(message) > 500 {
		message = message[:497] + "..."
	}
	var meta map[string]any
	if len(metadata) > 0 {
		meta = metadata[0]
	}
	return Decision{passed: false, message: message, metadata: meta}
}

// Precondition defines a check that runs before tool execution.
type Precondition struct {
	Name          string // Human-readable name for audit records.
	Tool          string // Tool name or "*" for all tools.
	Check         func(ctx context.Context, env toolcall.ToolCall) (Decision, error)
	When          func(ctx context.Context, env toolcall.ToolCall) bool
	Mode          string // "observe" for observe-mode; "" for enforce.
	Source        string // Decision source for audit (default: "precondition").
	Effect        string // "block" (default) or "ask".
	Timeout       int    // Approval timeout in seconds (default: 300).
	TimeoutEffect string // "block" (default) or "allow".
}

// Postcondition defines a check that runs after tool execution.
type Postcondition struct {
	Name           string // Human-readable name for audit records.
	Tool           string // Tool name or "*" for all tools.
	Check          func(ctx context.Context, env toolcall.ToolCall, response any) (Decision, error)
	When           func(ctx context.Context, env toolcall.ToolCall) bool
	Mode           string           // "observe" for observe-mode; "" for enforce.
	Source         string           // Decision source for audit (default: "postcondition").
	Effect         string           // "warn" (default), "redact", or "block".
	RedactPatterns []*regexp.Regexp // Compiled regex patterns for redact effect.
}

// SessionRule defines a check that evaluates session-level state.
// The Check function receives a *session.Session as the session parameter.
type SessionRule struct {
	Name   string // Human-readable name for audit records.
	Check  func(ctx context.Context, session any) (Decision, error)
	Mode   string // "observe" for observe-mode; "" for enforce.
	Source string // Decision source for audit (default: "session_rule").
}
