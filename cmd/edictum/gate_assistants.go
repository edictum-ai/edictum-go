// gate_assistants.go — Assistant registry, Claude Code, and Cursor
// install/uninstall logic.
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
	"cursor":      {install: installCursor, uninstall: uninstallCursor},
	"copilot":     {install: installCopilot, uninstall: uninstallCopilot},
	"gemini":      {install: installGemini, uninstall: uninstallGemini},
	"opencode":    {install: installOpenCode, uninstall: uninstallOpenCode},
}

func supportedAssistants() []string {
	return []string{"claude-code", "copilot", "cursor", "gemini", "opencode"}
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

// --- Cursor ---

func installCursor() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	hooksPath := filepath.Join(home, ".cursor", "hooks.json")
	config, err := readJSONFile(hooksPath)
	if err != nil {
		config = map[string]any{}
	}

	hookEntry := map[string]any{"command": "edictum gate check --format cursor", "timeout": float64(5)}
	hooks := ensureMap(config, "hooks")
	preToolUse := ensureSlice(hooks, "preToolUse")

	if containsHookMarkerDirect(preToolUse, "command") {
		return "Edictum gate hook already installed in Cursor hooks", nil
	}

	preToolUse = append(preToolUse, hookEntry)
	hooks["preToolUse"] = preToolUse
	config["hooks"] = hooks

	if wErr := writeJSONFileAtomic(hooksPath, config); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Installed edictum gate hook in %s", hooksPath), nil
}

func uninstallCursor() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	hooksPath := filepath.Join(home, ".cursor", "hooks.json")
	config, err := readJSONFile(hooksPath)
	if err != nil {
		return "No Cursor hooks found", nil //nolint:nilerr // File not found is not an error for uninstall.
	}

	hooks, _ := config["hooks"].(map[string]any)
	if hooks == nil {
		return "Edictum gate hook not found in Cursor hooks", nil
	}
	preToolUse, _ := hooks["preToolUse"].([]any)

	filtered, removed := filterDirectEntries(preToolUse, "command")
	if !removed {
		return "Edictum gate hook not found in Cursor hooks", nil
	}

	hooks["preToolUse"] = filtered
	config["hooks"] = hooks
	if wErr := writeJSONFileAtomic(hooksPath, config); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Removed edictum gate hook from %s", hooksPath), nil
}
