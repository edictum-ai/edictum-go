// gate_assistants.go — Assistant registry and Claude Code install/uninstall logic.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Assistant install/uninstall registry
// ---------------------------------------------------------------------------

const edictumHookMarker = "edictum gate check"

type assistantOps struct {
	install   func() (string, error)
	uninstall func() (string, error)
}

var assistantRegistry = map[string]assistantOps{
	"claude-code": {install: installClaudeCode, uninstall: uninstallClaudeCode},
	"copilot":     {install: installCopilot, uninstall: uninstallCopilot},
	"opencode":    {install: installOpenCode, uninstall: uninstallOpenCode},
}

func supportedAssistants() []string {
	return []string{"claude-code", "copilot", "opencode"}
}

func installAssistant(name string) (string, error) {
	ops, ok := assistantRegistry[name]
	if !ok {
		return "", fmt.Errorf("unsupported assistant %q; supported: %s", name, strings.Join(supportedAssistants(), ", "))
	}
	return ops.install()
}

func uninstallAssistant(name string) (string, error) {
	ops, ok := assistantRegistry[name]
	if !ok {
		return "", fmt.Errorf("unsupported assistant %q; supported: %s", name, strings.Join(supportedAssistants(), ", "))
	}
	return ops.uninstall()
}

// --- Claude Code ---

func installClaudeCode() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	settings, err := readJSONFile(settingsPath)
	if err != nil {
		settings = map[string]any{}
	}

	hookEntry := map[string]any{"type": "command", "command": "edictum gate check --format claude-code"}
	matcherEntry := map[string]any{"matcher": "", "hooks": []any{hookEntry}}

	hooks := ensureMap(settings, "hooks")
	preToolUse := ensureSlice(hooks, "PreToolUse")

	if containsHookMarker(preToolUse, "hooks", "command") {
		return "Edictum gate hook already installed in Claude Code settings", nil
	}

	preToolUse = append(preToolUse, matcherEntry)
	hooks["PreToolUse"] = preToolUse
	settings["hooks"] = hooks

	if wErr := writeJSONFileAtomic(settingsPath, settings); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Installed edictum gate hook in %s", settingsPath), nil
}

func uninstallClaudeCode() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	settings, err := readJSONFile(settingsPath)
	if err != nil {
		return "No Claude Code settings found", nil //nolint:nilerr // File not found is not an error for uninstall.
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return "Edictum gate hook not found in Claude Code settings", nil
	}
	preToolUse, _ := hooks["PreToolUse"].([]any)

	filtered, removed := filterHookEntries(preToolUse, "hooks", "command")
	if !removed {
		return "Edictum gate hook not found in Claude Code settings", nil
	}

	hooks["PreToolUse"] = filtered
	settings["hooks"] = hooks
	if wErr := writeJSONFileAtomic(settingsPath, settings); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Removed edictum gate hook from %s", settingsPath), nil
}
