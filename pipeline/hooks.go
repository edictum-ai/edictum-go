package pipeline

import (
	"context"

	"github.com/edictum-ai/edictum-go/toolcall"
)

// HookResult represents the outcome of a hook evaluation.
type HookResult string

// HookResult values.
const (
	HookResultAllow HookResult = "allow"
	HookResultDeny  HookResult = "block"
)

// HookDecision is the result of a before/after hook.
type HookDecision struct {
	Result HookResult
	Reason string
}

// AllowHook creates an allow decision.
func AllowHook() HookDecision {
	return HookDecision{Result: HookResultAllow}
}

// DenyHook creates a deny decision with a reason (truncated to 500 chars).
// Truncation preserves readability: "xxx..." (497 chars + "...").
func DenyHook(reason string) HookDecision {
	if len(reason) > 500 {
		reason = reason[:497] + "..."
	}
	return HookDecision{Result: HookResultDeny, Reason: reason}
}

// BeforeHookFunc is the signature for before-execution hooks.
type BeforeHookFunc func(ctx context.Context, env toolcall.ToolCall) (HookDecision, error)

// AfterHookFunc is the signature for after-execution hooks.
type AfterHookFunc func(ctx context.Context, env toolcall.ToolCall, result any) error

// HookRegistration binds a hook callback to a phase and tool pattern.
type HookRegistration struct {
	Phase  string         // "before" or "after"
	Tool   string         // Tool name, glob pattern, or "*" for all.
	Before BeforeHookFunc // Set for phase="before".
	After  AfterHookFunc  // Set for phase="after".
	When   func(ctx context.Context, env toolcall.ToolCall) bool
	Name   string // Human-readable name for audit.
}

// HookName returns the hook's name, falling back to "anonymous".
func (h HookRegistration) HookName() string {
	if h.Name != "" {
		return h.Name
	}
	return "anonymous"
}
