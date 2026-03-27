// gate_assistants.go — Assistant install/uninstall logic for each coding
// assistant (Claude Code, Cursor, Copilot, Gemini, OpenCode) and detection
// of which assistants are currently installed.
//
// NOTE: This file exceeds the 200-line guideline because it contains
// repetitive per-assistant install/uninstall code. Splitting further would
// scatter closely related logic across too many files.
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

	// Check if already installed.
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

// --- Copilot ---

func installCopilot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	hooksPath := filepath.Join(cwd, ".github", "hooks", "hooks.json")
	config, err := readJSONFile(hooksPath)
	if err != nil {
		config = map[string]any{}
	}

	if _, ok := config["version"]; !ok {
		config["version"] = float64(1)
	}

	hookEntry := map[string]any{
		"type": "command", "bash": "edictum gate check --format copilot", "timeoutSec": float64(5),
	}
	hooks := ensureMap(config, "hooks")
	preToolUse := ensureSlice(hooks, "preToolUse")

	if containsHookMarkerDirect(preToolUse, "bash") {
		return "Edictum gate hook already installed for Copilot CLI", nil
	}

	preToolUse = append(preToolUse, hookEntry)
	hooks["preToolUse"] = preToolUse
	config["hooks"] = hooks

	if wErr := writeJSONFileAtomic(hooksPath, config); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Installed edictum gate hook in %s", hooksPath), nil
}

func uninstallCopilot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	hooksPath := filepath.Join(cwd, ".github", "hooks", "hooks.json")
	config, err := readJSONFile(hooksPath)
	if err != nil {
		return "No Copilot CLI hooks found", nil //nolint:nilerr // File not found is not an error for uninstall.
	}

	hooks, _ := config["hooks"].(map[string]any)
	if hooks == nil {
		return "Edictum gate hook not found in Copilot CLI hooks", nil
	}
	preToolUse, _ := hooks["preToolUse"].([]any)

	filtered, removed := filterDirectEntries(preToolUse, "bash")
	if !removed {
		return "Edictum gate hook not found in Copilot CLI hooks", nil
	}

	hooks["preToolUse"] = filtered
	config["hooks"] = hooks
	if wErr := writeJSONFileAtomic(hooksPath, config); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Removed edictum gate hook from %s", hooksPath), nil
}

// --- Gemini CLI ---

const geminiHookScript = `#!/usr/bin/env bash
# Edictum Gate hook for Gemini CLI
# Generated by: edictum gate install gemini
input=$(cat)
result=$(echo "$input" | edictum gate check --format gemini 2>/dev/null)
exit_code=$?
if [ $exit_code -eq 1 ]; then
  echo "$result" >&2
  exit 1
fi
# Fail-closed: if edictum is missing or crashed (non-0, non-1), deny the call
if [ $exit_code -ne 0 ]; then
  echo "Edictum gate check failed (exit $exit_code)" >&2
  exit 1
fi
echo "{}"
exit 0
`

func installGemini() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	settingsPath := filepath.Join(cwd, ".gemini", "settings.json")

	// Check if already installed.
	if existing, rErr := readJSONFile(settingsPath); rErr == nil {
		if containsGeminiHook(existing) {
			return "Edictum gate hook already installed for Gemini CLI", nil
		}
	}

	// Write hook script.
	hooksDir := filepath.Join(cwd, ".gemini", "hooks")
	if mkErr := os.MkdirAll(hooksDir, 0o755); mkErr != nil {
		return "", mkErr
	}
	scriptPath := filepath.Join(hooksDir, "edictum-gate.sh")
	if wErr := os.WriteFile(scriptPath, []byte(geminiHookScript), 0o755); wErr != nil {
		return "", wErr
	}

	// Register in settings.json.
	settings, _ := readJSONFile(settingsPath)
	if settings == nil {
		settings = map[string]any{}
	}
	hookEntry := map[string]any{
		"matcher": "*",
		"hooks": []any{
			map[string]any{
				"name":    "edictum-gate",
				"type":    "command",
				"command": ".gemini/hooks/edictum-gate.sh",
			},
		},
	}
	hooks := ensureMap(settings, "hooks")
	beforeTool := ensureSlice(hooks, "BeforeTool")
	beforeTool = append(beforeTool, hookEntry)
	hooks["BeforeTool"] = beforeTool
	settings["hooks"] = hooks

	if wErr := writeJSONFileAtomic(settingsPath, settings); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Installed edictum gate hook at %s (registered in %s)", scriptPath, settingsPath), nil
}

func uninstallGemini() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	scriptPath := filepath.Join(cwd, ".gemini", "hooks", "edictum-gate.sh")
	settingsPath := filepath.Join(cwd, ".gemini", "settings.json")

	removedScript := false
	if _, sErr := os.Stat(scriptPath); sErr == nil {
		if rmErr := os.Remove(scriptPath); rmErr == nil {
			removedScript = true
		}
	}

	removedSetting := false
	if settings, rErr := readJSONFile(settingsPath); rErr == nil {
		hooks, _ := settings["hooks"].(map[string]any)
		if hooks != nil {
			beforeTool, _ := hooks["BeforeTool"].([]any)
			filtered, did := filterGeminiEntries(beforeTool)
			if did {
				removedSetting = true
				hooks["BeforeTool"] = filtered
				settings["hooks"] = hooks
				_ = writeJSONFileAtomic(settingsPath, settings)
			}
		}
	}

	if removedScript || removedSetting {
		return fmt.Sprintf("Removed edictum gate hook from %s", filepath.Join(cwd, ".gemini")), nil
	}
	return "Edictum gate hook not found for Gemini CLI", nil
}

func containsGeminiHook(settings map[string]any) bool {
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return false
	}
	beforeTool, _ := hooks["BeforeTool"].([]any)
	for _, entry := range beforeTool {
		m, _ := entry.(map[string]any)
		if m == nil {
			continue
		}
		hs, _ := m["hooks"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if hm == nil {
				continue
			}
			name, _ := hm["name"].(string)
			cmd, _ := hm["command"].(string)
			if strings.Contains(name, "edictum") || strings.Contains(cmd, "edictum") {
				return true
			}
		}
	}
	return false
}

func filterGeminiEntries(entries []any) ([]any, bool) {
	var filtered []any
	removed := false
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			filtered = append(filtered, entry)
			continue
		}
		hs, _ := m["hooks"].([]any)
		var clean []any
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if hm == nil {
				clean = append(clean, h)
				continue
			}
			name, _ := hm["name"].(string)
			cmd, _ := hm["command"].(string)
			if strings.Contains(name, "edictum") || strings.Contains(cmd, "edictum") {
				removed = true
				continue
			}
			clean = append(clean, h)
		}
		if len(clean) > 0 {
			m["hooks"] = clean
			filtered = append(filtered, m)
		}
	}
	return filtered, removed
}

// --- OpenCode ---

const opencodePluginContent = `// Edictum Gate plugin for OpenCode
// Generated by: edictum gate install opencode
import { spawnSync } from "child_process";

export const EdictumGate = async ({ directory }) => {
  return {
    "tool.execute.before": async (input, output) => {
      const payload = JSON.stringify({
        tool: input.tool,
        args: output.args,
        directory: directory || process.cwd(),
      });
      try {
        const proc = spawnSync(
          "edictum",
          ["gate", "check", "--format", "opencode"],
          { input: payload, encoding: "utf-8", timeout: 5000, shell: false }
        );
        if (proc.error) {
          throw new Error("Edictum gate check failed: " + proc.error.message);
        }
        const result = (proc.stdout || "").trim();
        if (!result) return;
        const parsed = JSON.parse(result);
        if (parsed.allow === false) {
          throw new Error(parsed.reason || "Denied by edictum gate");
        }
      } catch (e) {
        if (e.message && e.message.startsWith("Denied")) throw e;
        if (e.message && e.message.startsWith("Contract")) throw e;
        // Fail-closed: unknown error blocks the tool call
        throw new Error("Edictum gate check failed: " + e.message);
      }
    }
  };
};
`

func installOpenCode() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	pluginsDir := filepath.Join(home, ".opencode", "plugins")
	if mkErr := os.MkdirAll(pluginsDir, 0o755); mkErr != nil {
		return "", mkErr
	}
	pluginPath := filepath.Join(pluginsDir, "edictum-gate.ts")

	// Idempotency check.
	if data, rErr := os.ReadFile(pluginPath); rErr == nil {
		if strings.Contains(string(data), edictumHookMarker) {
			return "Edictum gate plugin already installed for OpenCode", nil
		}
	}

	if wErr := os.WriteFile(pluginPath, []byte(opencodePluginContent), 0o644); wErr != nil {
		return "", wErr
	}
	return fmt.Sprintf("Installed edictum gate plugin at %s", pluginPath), nil
}

func uninstallOpenCode() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	pluginPath := filepath.Join(home, ".opencode", "plugins", "edictum-gate.ts")

	if _, sErr := os.Stat(pluginPath); os.IsNotExist(sErr) {
		return "Edictum gate plugin not found for OpenCode", nil
	}
	if rmErr := os.Remove(pluginPath); rmErr != nil {
		return "", rmErr
	}
	return fmt.Sprintf("Removed edictum gate plugin from %s", pluginPath), nil
}

// ---------------------------------------------------------------------------
// Detect installed assistants (for status)
// ---------------------------------------------------------------------------

func detectInstalledAssistants() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var installed []string

	// Claude Code.
	if settings, rErr := readJSONFile(filepath.Join(home, ".claude", "settings.json")); rErr == nil {
		hooks, _ := settings["hooks"].(map[string]any)
		if hooks != nil {
			ptu, _ := hooks["PreToolUse"].([]any)
			if containsHookMarker(ptu, "hooks", "command") {
				installed = append(installed, "claude-code")
			}
		}
	}

	// Cursor.
	if config, rErr := readJSONFile(filepath.Join(home, ".cursor", "hooks.json")); rErr == nil {
		hooks, _ := config["hooks"].(map[string]any)
		if hooks != nil {
			ptu, _ := hooks["preToolUse"].([]any)
			if containsHookMarkerDirect(ptu, "command") {
				installed = append(installed, "cursor")
			}
		}
	}

	// Copilot (cwd-relative).
	if cwd, cwdErr := os.Getwd(); cwdErr == nil {
		if config, rErr := readJSONFile(filepath.Join(cwd, ".github", "hooks", "hooks.json")); rErr == nil {
			hooks, _ := config["hooks"].(map[string]any)
			if hooks != nil {
				ptu, _ := hooks["preToolUse"].([]any)
				if containsHookMarkerDirect(ptu, "bash") {
					installed = append(installed, "copilot")
				}
			}
		}
	}

	// Gemini (cwd-relative).
	if cwd, cwdErr := os.Getwd(); cwdErr == nil {
		scriptPath := filepath.Join(cwd, ".gemini", "hooks", "edictum-gate.sh")
		if _, sErr := os.Stat(scriptPath); sErr == nil {
			installed = append(installed, "gemini")
		}
	}

	// OpenCode.
	pluginPath := filepath.Join(home, ".opencode", "plugins", "edictum-gate.ts")
	if _, sErr := os.Stat(pluginPath); sErr == nil {
		installed = append(installed, "opencode")
	}

	return installed
}
