// Package pipeline implements the 5-stage governance pipeline.
package pipeline

// OperationLimits defines caps on tool call attempts and executions.
//
// Two counter types:
//   - MaxAttempts: caps ALL PreToolUse events (including denied)
//   - MaxToolCalls: caps EXECUTIONS only (PostToolUse)
//
// Both are checked. Whichever fires first wins.
type OperationLimits struct {
	MaxAttempts     int            // Default: 500. All pre-execution events.
	MaxToolCalls    int            // Default: 200. Executions only.
	MaxCallsPerTool map[string]int // Per-tool execution caps.
}

// DefaultLimits returns OperationLimits with default values.
func DefaultLimits() OperationLimits {
	return OperationLimits{
		MaxAttempts:     500,
		MaxToolCalls:    200,
		MaxCallsPerTool: map[string]int{},
	}
}
