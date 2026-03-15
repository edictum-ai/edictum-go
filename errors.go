package edictum

import "fmt"

// EdictumError is the base error type for all edictum errors.
type EdictumError struct {
	Message string
}

func (e *EdictumError) Error() string {
	return e.Message
}

// DeniedError indicates a tool call was denied by a contract or hook.
type DeniedError struct {
	Reason         string
	DecisionSource string
	DecisionName   string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("edictum denied: %s (source=%s, name=%s)", e.Reason, e.DecisionSource, e.DecisionName)
}

// ConfigError indicates a configuration or load-time error.
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("edictum config error: %s", e.Message)
}

// ToolError indicates a tool execution failure.
type ToolError struct {
	Message string
}

func (e *ToolError) Error() string {
	return fmt.Sprintf("edictum tool error: %s", e.Message)
}
