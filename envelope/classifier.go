package envelope

import "strings"

// BashClassifier classifies bash commands by side effect.

// readAllowlist contains commands classified as READ.
var readAllowlist = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "less": true,
	"more": true, "wc": true, "file": true, "stat": true, "find": true,
	"grep": true, "rg": true, "ag": true, "ack": true, "which": true,
	"whereis": true, "type": true, "echo": true, "printf": true,
	"pwd": true, "whoami": true, "id": true, "uname": true, "date": true,
	"env": true, "printenv": true, "git status": true, "git log": true,
	"git diff": true, "git show": true, "git branch": true,
}

// shellOperators are shell metacharacters that indicate IRREVERSIBLE side effects.
var shellOperators = []string{
	"|", ";", "&&", "||", "$(", "`", "${", "<(", "<<", ">", ">>",
	"\n", "\r", "$((",
}

// ClassifyBash classifies a bash command string by its side effect.
func ClassifyBash(command string) SideEffect {
	command = strings.TrimSpace(command)
	if command == "" {
		return SideEffectRead
	}

	// Check for shell operators first — any metachar means IRREVERSIBLE
	for _, op := range shellOperators {
		if strings.Contains(command, op) {
			return SideEffectIrreversible
		}
	}

	// Extract the first word/command
	firstWord := strings.Fields(command)[0]

	// Check multi-word commands (e.g., "git status")
	if readAllowlist[command] {
		return SideEffectRead
	}

	// Check single-word command
	if readAllowlist[firstWord] {
		return SideEffectRead
	}

	return SideEffectIrreversible
}

// ToolRegistry maps tool names to their side effect classification.
type ToolRegistry struct {
	tools map[string]toolConfig
}

type toolConfig struct {
	sideEffect SideEffect
	idempotent bool
}

// NewToolRegistry creates a new empty ToolRegistry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{tools: make(map[string]toolConfig)}
}

// Register registers a tool with its side effect classification.
func (r *ToolRegistry) Register(name string, se SideEffect, idempotent bool) {
	r.tools[name] = toolConfig{sideEffect: se, idempotent: idempotent}
}

// Classify returns the side effect and idempotency of a tool.
// Unregistered tools return IRREVERSIBLE, false.
func (r *ToolRegistry) Classify(name string) (SideEffect, bool) {
	if cfg, ok := r.tools[name]; ok {
		return cfg.sideEffect, cfg.idempotent
	}
	return SideEffectIrreversible, false
}
