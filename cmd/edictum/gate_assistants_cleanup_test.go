package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityLegacyCursorUninstallRemovesOnlyGeneratedHook(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	hooksPath := filepath.Join(home, ".cursor", "hooks.json")
	config := map[string]any{
		"hooks": map[string]any{
			"preToolUse": []any{
				map[string]any{"command": legacyCursorCommand, "timeout": float64(5)},
				map[string]any{"command": "./user-hook.sh"},
			},
		},
	}
	if err := writeJSONFileAtomic(hooksPath, config); err != nil {
		t.Fatal(err)
	}

	message, err := uninstallAssistant("cursor")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "Removed legacy edictum gate hook") {
		t.Fatalf("message = %q, want cleanup confirmation", message)
	}

	got, err := readJSONFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := got["hooks"].(map[string]any)
	entries, _ := hooks["preToolUse"].([]any)
	if len(entries) != 1 {
		t.Fatalf("remaining hooks = %v, want one user hook", entries)
	}
	entry, _ := entries[0].(map[string]any)
	if entry["command"] != "./user-hook.sh" {
		t.Fatalf("remaining hook = %v, want user hook", entry)
	}
}

func TestSecurityLegacyGeminiUninstallRemovesOnlyGeneratedArtifacts(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	settingsPath := filepath.Join(root, ".gemini", "settings.json")
	scriptPath := filepath.Join(root, legacyGeminiCommand)
	settings := map[string]any{
		"hooks": map[string]any{
			"BeforeTool": []any{
				map[string]any{"matcher": "*", "hooks": []any{
					map[string]any{"name": "edictum-gate", "type": "command", "command": legacyGeminiCommand},
					map[string]any{"name": "user-hook", "type": "command", "command": "./user-hook.sh"},
				}},
			},
		},
	}
	if err := writeJSONFileAtomic(settingsPath, settings); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0o755); err != nil {
		t.Fatal(err)
	}
	legacyScript := "#!/bin/sh\n" + legacyGeminiGeneratedMark + "\n"
	if err := os.WriteFile(scriptPath, []byte(legacyScript), 0o755); err != nil { //nolint:gosec // Test fixture is an executable hook.
		t.Fatal(err)
	}

	message, err := uninstallAssistant("gemini")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "Removed legacy edictum gate hook") {
		t.Fatalf("message = %q, want cleanup confirmation", message)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Fatalf("generated script still exists: %v", err)
	}

	got, err := readJSONFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := got["hooks"].(map[string]any)
	entries, _ := hooks["BeforeTool"].([]any)
	if len(entries) != 1 {
		t.Fatalf("remaining hook groups = %v, want one group", entries)
	}
	entry, _ := entries[0].(map[string]any)
	nested, _ := entry["hooks"].([]any)
	if len(nested) != 1 {
		t.Fatalf("remaining hooks = %v, want one user hook", nested)
	}
	userHook, _ := nested[0].(map[string]any)
	if userHook["name"] != "user-hook" {
		t.Fatalf("remaining hook = %v, want user hook", userHook)
	}
}
