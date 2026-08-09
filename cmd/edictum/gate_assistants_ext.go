// gate_assistants_ext.go — Copilot install/uninstall logic.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

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
