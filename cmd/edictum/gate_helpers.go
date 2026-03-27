package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// Gate config types
// ---------------------------------------------------------------------------

type gateConfig struct {
	ServerURL     string   `json:"server_url"`
	APIKey        string   `json:"api_key"`
	ContractsPath string   `json:"contracts_path"`
	AuditPath     string   `json:"audit_path"`
	Installed     []string `json:"installed_assistants"`
}

// ---------------------------------------------------------------------------
// Gate directory and config I/O
// ---------------------------------------------------------------------------

func gateDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".edictum"), nil
}

func loadGateConfigDefault() (*gateConfig, error) {
	gateDir, err := gateDirectory()
	if err != nil {
		return nil, err
	}
	return loadGateConfig(filepath.Join(gateDir, "config.json"))
}

func loadGateConfig(path string) (*gateConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg gateConfig
	if jErr := json.Unmarshal(data, &cfg); jErr != nil {
		return nil, fmt.Errorf("parse config: %w", jErr)
	}
	return &cfg, nil
}

func writeGateConfig(path string, cfg *gateConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWrite(path, data)
}

func updateInstalledAssistants(assistant string, add bool) error {
	gateDir, err := gateDirectory()
	if err != nil {
		return err
	}
	configPath := filepath.Join(gateDir, "config.json")
	cfg, err := loadGateConfig(configPath)
	if err != nil {
		return err
	}

	if add {
		// Avoid duplicates.
		for _, a := range cfg.Installed {
			if a == assistant {
				return writeGateConfig(configPath, cfg)
			}
		}
		cfg.Installed = append(cfg.Installed, assistant)
	} else {
		filtered := cfg.Installed[:0]
		for _, a := range cfg.Installed {
			if a != assistant {
				filtered = append(filtered, a)
			}
		}
		cfg.Installed = filtered
	}
	return writeGateConfig(configPath, cfg)
}

// ---------------------------------------------------------------------------
// File utilities
// ---------------------------------------------------------------------------

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return mkErr
	}
	tmp := path + ".tmp"
	if wErr := os.WriteFile(tmp, data, 0o644); wErr != nil {
		return wErr
	}
	return os.Rename(tmp, path)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return atomicWrite(dst, data)
}

// ---------------------------------------------------------------------------
// WAL (write-ahead log) operations
// ---------------------------------------------------------------------------

type walEvent struct {
	Timestamp string `json:"timestamp"`
	ToolName  string `json:"tool_name"`
	Verdict   string `json:"verdict"`
	Assistant string `json:"assistant,omitempty"`
	User      string `json:"user,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func walFilePath(auditDir string) string {
	return filepath.Join(auditDir, fmt.Sprintf("wal-%s.jsonl", time.Now().UTC().Format("20060102")))
}

func appendWALEvent(auditDir string, event walEvent) error {
	if auditDir == "" {
		return nil
	}
	if mkErr := os.MkdirAll(auditDir, 0o755); mkErr != nil {
		return mkErr
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	f, err := os.OpenFile(walFilePath(auditDir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func readWALEvents(auditDir string, limit int, toolFilter, verdictFilter string) ([]walEvent, error) {
	if auditDir == "" {
		return nil, nil
	}
	files, err := filepath.Glob(filepath.Join(auditDir, "wal-*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var all []walEvent
	for _, f := range files {
		events, rErr := readJSONLFile(f)
		if rErr != nil {
			continue // skip corrupt files
		}
		all = append(all, events...)
	}

	// Apply filters.
	var filtered []walEvent
	for _, e := range all {
		if toolFilter != "" && e.ToolName != toolFilter {
			continue
		}
		if verdictFilter != "" && e.Verdict != verdictFilter {
			continue
		}
		filtered = append(filtered, e)
	}

	// Return last N events.
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	return filtered, nil
}

func readJSONLFile(path string) ([]walEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []walEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e walEvent
		if jErr := json.Unmarshal(line, &e); jErr != nil {
			continue // skip malformed lines
		}
		events = append(events, e)
	}
	return events, scanner.Err()
}

func countWALEvents(auditDir string) int {
	if auditDir == "" {
		return 0
	}
	files, _ := filepath.Glob(filepath.Join(auditDir, "wal-*.jsonl"))
	count := 0
	for _, f := range files {
		events, err := readJSONLFile(f)
		if err == nil {
			count += len(events)
		}
	}
	return count
}

func archiveWALFiles(auditDir string) error {
	files, err := filepath.Glob(filepath.Join(auditDir, "wal-*.jsonl"))
	if err != nil {
		return err
	}
	for _, f := range files {
		if rmErr := os.Remove(f); rmErr != nil {
			return rmErr
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Format parsing and output
// ---------------------------------------------------------------------------

// Tool name maps for each assistant format.
var cursorToolMap = map[string]string{
	"Shell": "Bash", "Read": "Read", "Write": "Write",
	"Edit": "Edit", "Task": "Task",
}

var copilotToolMap = map[string]string{
	"bash": "Bash", "edit": "Edit", "view": "Read", "create": "Write",
}

var geminiToolMap = map[string]string{
	"shell": "Bash", "run_shell_command": "Bash",
	"write_file": "Write", "read_file": "Read",
	"edit_file": "Edit", "replace_in_file": "Edit",
	"glob": "Glob", "list_files": "Glob",
	"grep": "Grep", "search_files": "Grep",
	"web_fetch": "WebFetch", "web_search": "WebSearch",
}

var opencodeToolMap = map[string]string{
	"bash": "Bash", "shell": "Bash", "read": "Read",
	"write": "Write", "patch": "Edit", "glob": "Glob",
	"grep": "Grep", "browser": "WebFetch",
}

var opencodeArgMap = map[string]string{
	"filePath": "file_path",
}

func parseFormatStdin(format string, raw []byte) (string, map[string]any, error) {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", nil, fmt.Errorf("invalid JSON in stdin")
	}

	switch format {
	case "claude-code", "raw":
		// Auto-detect Cursor when stdin contains Cursor-specific fields.
		if format == "claude-code" {
			if _, ok := data["cursor_version"]; ok {
				return parseCursorStdin(data)
			}
			if _, ok := data["workspace_roots"]; ok {
				return parseCursorStdin(data)
			}
		}
		return parseStandardStdin(data, nil)

	case "cursor":
		return parseCursorStdin(data)

	case "copilot":
		return parseCopilotStdin(data)

	case "gemini":
		return parseStandardStdin(data, geminiToolMap)

	case "opencode":
		return parseOpenCodeStdin(data)

	default:
		return parseStandardStdin(data, nil)
	}
}

func parseStandardStdin(data map[string]any, toolMap map[string]string) (string, map[string]any, error) {
	toolName, _ := data["tool_name"].(string)
	toolInput, _ := data["tool_input"].(map[string]any)
	if toolInput == nil {
		toolInput = map[string]any{}
	}
	if toolMap != nil {
		if mapped, ok := toolMap[toolName]; ok {
			toolName = mapped
		}
	}
	return toolName, toolInput, nil
}

func parseCursorStdin(data map[string]any) (string, map[string]any, error) {
	toolName, _ := data["tool_name"].(string)
	if mapped, ok := cursorToolMap[toolName]; ok {
		toolName = mapped
	}
	toolInput, _ := data["tool_input"].(map[string]any)
	if toolInput == nil {
		toolInput = map[string]any{}
	}
	return toolName, toolInput, nil
}

func parseCopilotStdin(data map[string]any) (string, map[string]any, error) {
	toolName, _ := data["toolName"].(string)
	if mapped, ok := copilotToolMap[toolName]; ok {
		toolName = mapped
	}
	// toolArgs is a JSON string in Copilot format.
	var toolInput map[string]any
	switch v := data["toolArgs"].(type) {
	case string:
		if jErr := json.Unmarshal([]byte(v), &toolInput); jErr != nil {
			toolInput = map[string]any{}
		}
	case map[string]any:
		toolInput = v
	default:
		toolInput = map[string]any{}
	}
	if toolInput == nil {
		toolInput = map[string]any{}
	}
	return toolName, toolInput, nil
}

func parseOpenCodeStdin(data map[string]any) (string, map[string]any, error) {
	toolName, _ := data["tool"].(string)
	if mapped, ok := opencodeToolMap[toolName]; ok {
		toolName = mapped
	}
	rawArgs, _ := data["args"].(map[string]any)
	if rawArgs == nil {
		rawArgs = map[string]any{}
	}
	// Normalize arg keys.
	toolInput := make(map[string]any, len(rawArgs))
	for k, v := range rawArgs {
		if mapped, ok := opencodeArgMap[k]; ok {
			toolInput[mapped] = v
		} else {
			toolInput[k] = v
		}
	}
	return toolName, toolInput, nil
}

func buildDenyReason(contractID, reason string) string {
	if contractID != "" && reason != "" {
		return fmt.Sprintf("Contract '%s': %s", contractID, reason)
	}
	if reason != "" {
		return reason
	}
	if contractID != "" {
		return fmt.Sprintf("Denied by contract '%s'", contractID)
	}
	return "Denied"
}

func writeCheckOutput(cmd *cobra.Command, format, verdict, contractID, reason string) error {
	w := cmd.OutOrStdout()
	var output any
	exitCode := 0

	switch format {
	case "claude-code":
		if verdict == "deny" {
			output = map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny",
					"permissionDecisionReason": buildDenyReason(contractID, reason),
				},
			}
		} else {
			output = map[string]any{}
		}

	case "cursor":
		if verdict == "deny" {
			output = map[string]any{
				"decision": "deny",
				"reason":   buildDenyReason(contractID, reason),
			}
		} else {
			output = map[string]any{"decision": "allow"}
		}

	case "copilot":
		if verdict == "deny" {
			output = map[string]any{
				"permissionDecision":       "deny",
				"permissionDecisionReason": buildDenyReason(contractID, reason),
			}
		} else {
			output = map[string]any{}
		}

	case "gemini":
		if verdict == "deny" {
			// Gemini: plain text reason, exit 2.
			fmt.Fprintln(w, buildDenyReason(contractID, reason))
			return &exitError{code: 2}
		}
		output = map[string]any{}

	case "opencode":
		if verdict == "deny" {
			output = map[string]any{
				"allow":  false,
				"reason": buildDenyReason(contractID, reason),
			}
		} else {
			output = map[string]any{"allow": true}
		}

	case "raw":
		result := map[string]any{"verdict": verdict}
		if contractID != "" {
			result["contract_id"] = contractID
		}
		if reason != "" {
			result["reason"] = reason
		}
		output = result
		if verdict == "deny" {
			exitCode = 1
		}

	default:
		output = map[string]any{"verdict": verdict}
	}

	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Fprintln(w, string(data))

	if exitCode != 0 {
		return &exitError{code: exitCode}
	}
	return nil
}

func writeCheckDeny(cmd *cobra.Command, format, reason string) error {
	return writeCheckOutput(cmd, format, "deny", "", reason)
}

// ---------------------------------------------------------------------------
// Guard loading for gate check
// ---------------------------------------------------------------------------

func buildGuardFromPath(path string) (*guard.Guard, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return guard.FromYAML(path, guard.WithEnvironment("development"))
	}
	return guard.FromYAML(path, guard.WithEnvironment("development"))
}

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
	ops := assistantRegistry[name]
	return ops.install()
}

func uninstallAssistant(name string) (string, error) {
	ops := assistantRegistry[name]
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
if [ $exit_code -eq 2 ]; then
  echo "$result" >&2
  exit 2
fi
# Fail-closed: if edictum is missing or crashed (non-0, non-2), deny the call
if [ $exit_code -ne 0 ]; then
  echo "Edictum gate check failed (exit $exit_code)" >&2
  exit 2
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

// ---------------------------------------------------------------------------
// JSON file helpers
// ---------------------------------------------------------------------------

func readJSONFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if jErr := json.Unmarshal(data, &m); jErr != nil {
		return nil, jErr
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func writeJSONFileAtomic(path string, data map[string]any) error {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		return mkErr
	}
	return atomicWrite(path, encoded)
}

func ensureMap(m map[string]any, key string) map[string]any {
	v, ok := m[key].(map[string]any)
	if !ok || v == nil {
		v = map[string]any{}
		m[key] = v
	}
	return v
}

func ensureSlice(m map[string]any, key string) []any {
	v, ok := m[key].([]any)
	if !ok {
		v = []any{}
		m[key] = v
	}
	return v
}

// containsHookMarker checks nested hook entries (Claude Code style: entries[].hooks[].command).
func containsHookMarker(entries []any, hooksKey, cmdKey string) bool {
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			continue
		}
		hs, _ := m[hooksKey].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if hm == nil {
				continue
			}
			cmd, _ := hm[cmdKey].(string)
			if strings.Contains(cmd, edictumHookMarker) {
				return true
			}
		}
	}
	return false
}

// containsHookMarkerDirect checks flat hook entries (Cursor/Copilot style: entries[].command).
func containsHookMarkerDirect(entries []any, cmdKey string) bool {
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			continue
		}
		cmd, _ := m[cmdKey].(string)
		if strings.Contains(cmd, edictumHookMarker) {
			return true
		}
	}
	return false
}

// filterHookEntries removes nested edictum hooks (Claude Code style).
func filterHookEntries(entries []any, hooksKey, cmdKey string) ([]any, bool) {
	var filtered []any
	removed := false
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			filtered = append(filtered, entry)
			continue
		}
		hs, _ := m[hooksKey].([]any)
		var clean []any
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if hm == nil {
				clean = append(clean, h)
				continue
			}
			cmd, _ := hm[cmdKey].(string)
			if strings.Contains(cmd, edictumHookMarker) {
				removed = true
				continue
			}
			clean = append(clean, h)
		}
		if len(clean) > 0 {
			m[hooksKey] = clean
			filtered = append(filtered, m)
		}
	}
	return filtered, removed
}

// filterDirectEntries removes flat edictum hooks (Cursor/Copilot style).
func filterDirectEntries(entries []any, cmdKey string) ([]any, bool) {
	var filtered []any
	removed := false
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			filtered = append(filtered, entry)
			continue
		}
		cmd, _ := m[cmdKey].(string)
		if strings.Contains(cmd, edictumHookMarker) {
			removed = true
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, removed
}

// ---------------------------------------------------------------------------
// HTTP and user helpers
// ---------------------------------------------------------------------------

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func postJSON(url, apiKey string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}
