package toolcall

import "strings"

// BashClassifier classifies bash commands by side effect.

// readAllowlist contains commands classified as READ.
// Multi-word entries (e.g. "git status") match via prefix: the command
// must equal the entry or start with entry + " ".
// Security note: env/printenv are NOT allowed — they leak secrets.
var readAllowlist = []string{
	"ls", "cat", "head", "tail", "less",
	"more", "wc", "file", "stat", "find",
	"grep", "rg", "ag", "ack", "which",
	"whereis", "type", "echo", "printf",
	"pwd", "whoami", "id", "uname", "date",
	"du", "df", "tree",
	"git status", "git log", "git diff", "git show",
	"git branch", "git remote", "git tag",
}

// shellOperators are shell metacharacters that indicate IRREVERSIBLE side effects.
// Order matters: "$" is checked early so it catches $(), ${}, and bare $VAR.
var shellOperators = []string{
	"\n", "\r", "<(", "<<", "$", "${", ">", ">>", "|", ";", "&&", "||",
	"$(", "`", "#{",
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

	// Check against allowlist with prefix matching.
	// "git status" matches "git status" and "git status --short".
	for _, allowed := range readAllowlist {
		if command == allowed || strings.HasPrefix(command, allowed+" ") {
			return SideEffectRead
		}
	}

	return SideEffectIrreversible
}

// ToolRegistry maps tool names to their side effect classification.
// ToolRegistry is not safe for concurrent Register and Classify.
// Register all tools before passing to a Guard.
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
