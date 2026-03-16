// Package sandbox provides path, command, and domain sandboxing for tool calls.
//
// Sandbox contracts extract resources (paths, commands, domains/URLs) from
// tool call envelopes and check them against configurable boundaries.
// All paths are resolved via filepath.EvalSymlinks to handle both ".."
// traversals and symlink escapes. TOCTOU caveat: a symlink created after
// evaluation but before tool execution is not caught; full mitigation
// requires OS-level enforcement.
package sandbox

// Config describes sandbox boundaries for a tool call.
type Config struct {
	// Within lists allowed path prefixes. Every extracted path must fall
	// within at least one prefix. Paths are resolved via filepath.EvalSymlinks
	// at config construction time.
	Within []string

	// NotWithin lists excluded path prefixes. Any path matching an exclusion
	// is denied even if it falls within an allowed prefix.
	NotWithin []string

	// AllowedCommands lists permitted first-token commands (e.g. "ls", "cat").
	AllowedCommands []string

	// AllowedDomains lists domain glob patterns that URLs must match.
	AllowedDomains []string

	// BlockedDomains lists domain glob patterns that deny matching URLs.
	// Checked before AllowedDomains.
	BlockedDomains []string

	// Message is the denial message. Default: "Tool call outside sandbox boundary."
	Message string
}

// defaultMessage is used when Config.Message is empty.
const defaultMessage = "Tool call outside sandbox boundary."

// message returns the configured message or the default.
func (c Config) message() string {
	if c.Message != "" {
		return c.Message
	}
	return defaultMessage
}
