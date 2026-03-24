package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/internal/shlex"
)

// redirectPrefixRe matches shell redirection operators at the start of a token.
// Matches: >>, >, <<, <, or fd-prefixed variants like 2>, 2>>.
var redirectPrefixRe = regexp.MustCompile(`^(?:\d*>>|>>|\d*>|>|<<|<)`)

var shellOperators = []string{
	"\n", "\r", "<(", "<<", "$", "${", ">", ">>", "|", ";", "&&", "||",
	"$(", "`", "#{",
}

// pathArgKeys are argument keys that conventionally hold file paths.
var pathArgKeys = map[string]bool{
	"path":        true,
	"file_path":   true,
	"filePath":    true,
	"directory":   true,
	"dir":         true,
	"folder":      true,
	"target":      true,
	"destination": true,
	"source":      true,
	"src":         true,
	"dst":         true,
}

// ExtractPaths extracts file paths from an envelope for sandbox evaluation.
//
// Strategy (priority order):
//  1. env.FilePath() convenience field
//  2. Args values with path-like keys (path, file_path, filePath, etc.)
//  3. Any arg string value starting with /
//  4. Parse bash_command for /-prefixed tokens (shell-aware)
//
// All paths are resolved via filepath.EvalSymlinks (handles both ".."
// traversals AND symlinks). Non-existent paths fall back to filepath.Clean.
func ExtractPaths(env envelope.ToolEnvelope) []string {
	var paths []string
	seen := make(map[string]bool)

	add := func(p string) {
		if p == "" {
			return
		}
		p = resolvePath(p)
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// 1. Envelope convenience field
	if fp := env.FilePath(); fp != "" {
		add(fp)
	}

	args := env.Args()

	// 2. Path-like arg keys
	for key, value := range args {
		if s, ok := value.(string); ok && pathArgKeys[key] {
			add(s)
		}
	}

	// 3. Any arg value starting with /
	for key, value := range args {
		if s, ok := value.(string); ok && strings.HasPrefix(s, "/") && !pathArgKeys[key] {
			add(s)
		}
	}

	// 4. Parse command string for path tokens (shell-aware)
	cmd := env.BashCommand()
	if cmd == "" {
		if v, ok := args["command"]; ok {
			if s, ok := v.(string); ok {
				cmd = s
			}
		}
	}
	if cmd != "" {
		for _, token := range tokenizeCommand(cmd) {
			if strings.HasPrefix(token, "/") {
				add(token)
			}
		}
	}

	return paths
}

// ExtractCommand extracts the first command token from an envelope.
//
// If the command string begins with a shell redirect operator
// (e.g. "> echo bad_cmd"), the actual command cannot be reliably
// determined. Returns "\x00" sentinel that never matches any
// allowed-command list (fail-closed).
//
// Returns "" if no command is present.
func ExtractCommand(env envelope.ToolEnvelope) string {
	cmd := env.BashCommand()
	if cmd == "" {
		args := env.Args()
		if v, ok := args["command"]; ok {
			if s, ok := v.(string); ok {
				cmd = s
			}
		}
	}
	if cmd == "" {
		return ""
	}

	stripped := strings.TrimSpace(cmd)
	if stripped == "" {
		return ""
	}

	if hasShellOperator(stripped) {
		return "\x00"
	}

	// If the raw first whitespace-token starts with a redirect operator,
	// the "command" is actually a redirect target. Fail closed.
	rawFirst := strings.Fields(stripped)[0]
	if redirectPrefixRe.MatchString(rawFirst) {
		return "\x00"
	}

	tokens := tokenizeCommand(stripped)
	if len(tokens) == 0 {
		return ""
	}
	return tokens[0]
}

// tokenizeCommand performs shell-aware tokenization of a command string.
// Strips shell redirection operators from token prefixes so paths after
// redirects (e.g. ">/etc/passwd", "</etc/shadow") are exposed.
func tokenizeCommand(cmd string) []string {
	rawTokens := shlex.MustSplit(cmd)
	tokens := make([]string, 0, len(rawTokens))
	for _, t := range rawTokens {
		stripped := redirectPrefixRe.ReplaceAllString(t, "")
		if stripped != "" {
			tokens = append(tokens, stripped)
		}
	}
	return tokens
}

// resolvePath resolves a path via filepath.EvalSymlinks. Falls back to
// filepath.Clean for non-existent paths (still handles ".." traversals).
func resolvePath(p string) string {
	if p == "" {
		return ""
	}

	cleaned := filepath.Clean(p)
	if abs, err := filepath.Abs(cleaned); err == nil {
		cleaned = abs
	}

	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return resolved
	}

	parts := make([]string, 0, 4)
	current := cleaned
	existingPrefix := deepestExistingPrefix(cleaned)
	for {
		if current == existingPrefix {
			break
		}

		parts = append(parts, filepath.Base(current))
		current = filepath.Dir(current)
	}

	if resolved, err := filepath.EvalSymlinks(existingPrefix); err == nil {
		for i := len(parts) - 1; i >= 0; i-- {
			resolved = filepath.Join(resolved, parts[i])
		}
		return filepath.Clean(resolved)
	}

	return filepath.Clean(cleaned)
}

func hasShellOperator(command string) bool {
	for _, op := range shellOperators {
		if strings.Contains(command, op) {
			return true
		}
	}
	return false
}

func pathExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func deepestExistingPrefix(p string) string {
	current := p
	for {
		if pathExists(current) {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return current
		}
		current = parent
	}
}
