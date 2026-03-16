// Package envelope defines the ToolEnvelope type and tool classification.
package envelope

import (
	"fmt"
	"strings"
	"unicode"
)

// SideEffect classifies the impact of a tool call.
type SideEffect string

// SideEffect classification values.
const (
	SideEffectPure         SideEffect = "pure"
	SideEffectRead         SideEffect = "read"
	SideEffectWrite        SideEffect = "write"
	SideEffectIrreversible SideEffect = "irreversible"
)

// ToolEnvelope is an immutable snapshot of a tool call.
// Fields are unexported — use getter methods.
type ToolEnvelope struct {
	toolName    string
	args        map[string]any
	callID      string
	runID       string
	callIndex   int
	parentCall  string
	sideEffect  SideEffect
	idempotent  bool
	environment string
	timestamp   string
	caller      string
	toolUseID   string
	principal   *Principal
	bashCommand string
	filePath    string
	metadata    map[string]any
}

// ToolName returns the tool name.
func (e ToolEnvelope) ToolName() string { return e.toolName }

// Args returns a copy of the tool arguments.
func (e ToolEnvelope) Args() map[string]any {
	if e.args == nil {
		return nil
	}
	cp := make(map[string]any, len(e.args))
	for k, v := range e.args {
		cp[k] = v
	}
	return cp
}

// CallID returns the call ID.
func (e ToolEnvelope) CallID() string { return e.callID }

// RunID returns the run ID.
func (e ToolEnvelope) RunID() string { return e.runID }

// CallIndex returns the call index.
func (e ToolEnvelope) CallIndex() int { return e.callIndex }

// ParentCallID returns the parent call ID.
func (e ToolEnvelope) ParentCallID() string { return e.parentCall }

// SideEffect returns the classified side effect.
func (e ToolEnvelope) SideEffect() SideEffect { return e.sideEffect }

// Idempotent returns whether the tool call is idempotent.
func (e ToolEnvelope) Idempotent() bool { return e.idempotent }

// Environment returns the environment name.
func (e ToolEnvelope) Environment() string { return e.environment }

// Timestamp returns the timestamp.
func (e ToolEnvelope) Timestamp() string { return e.timestamp }

// Caller returns the caller identifier.
func (e ToolEnvelope) Caller() string { return e.caller }

// ToolUseID returns the tool use ID.
func (e ToolEnvelope) ToolUseID() string { return e.toolUseID }

// Principal returns the principal (nil if not set).
func (e ToolEnvelope) Principal() *Principal { return e.principal }

// BashCommand returns the extracted bash command.
func (e ToolEnvelope) BashCommand() string { return e.bashCommand }

// FilePath returns the extracted file path.
func (e ToolEnvelope) FilePath() string { return e.filePath }

// Metadata returns a copy of the metadata.
func (e ToolEnvelope) Metadata() map[string]any {
	if e.metadata == nil {
		return nil
	}
	cp := make(map[string]any, len(e.metadata))
	for k, v := range e.metadata {
		cp[k] = v
	}
	return cp
}

// ValidateToolName validates a tool name, rejecting empty, control chars, and path separators.
func ValidateToolName(name string) error {
	if name == "" {
		return fmt.Errorf("tool name must not be empty")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("tool name must not contain control characters")
		}
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("tool name must not contain path separators")
	}
	return nil
}
