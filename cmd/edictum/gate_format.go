package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// Guard loading for gate check
// ---------------------------------------------------------------------------

func buildGuardFromPath(path string) (*guard.Guard, error) {
	return guard.FromYAML(path)
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

	var toolName string
	var toolArgs map[string]any
	var parseErr error

	switch format {
	case "claude-code", "raw":
		// Auto-detect Cursor when stdin contains Cursor-specific fields.
		if format == "claude-code" {
			if _, ok := data["cursor_version"]; ok {
				toolName, toolArgs, parseErr = parseCursorStdin(data)
				break
			}
			if _, ok := data["workspace_roots"]; ok {
				toolName, toolArgs, parseErr = parseCursorStdin(data)
				break
			}
		}
		toolName, toolArgs, parseErr = parseStandardStdin(data, nil)

	case "cursor":
		toolName, toolArgs, parseErr = parseCursorStdin(data)

	case "copilot":
		toolName, toolArgs, parseErr = parseCopilotStdin(data)

	case "gemini":
		toolName, toolArgs, parseErr = parseStandardStdin(data, geminiToolMap)

	case "opencode":
		toolName, toolArgs, parseErr = parseOpenCodeStdin(data)

	default:
		return "", nil, fmt.Errorf("unsupported format %q; supported: claude-code, cursor, copilot, gemini, opencode, raw", format)
	}

	if parseErr != nil {
		return "", nil, parseErr
	}
	// Fail-closed: empty or malformed tool name bypasses tool-specific rules.
	if toolName == "" {
		return "", nil, fmt.Errorf("tool_name is required and must not be empty")
	}
	// Reject tool names with null bytes, control characters, or path
	// separators — these bypass tool-matching logic in rules.
	if err := toolcall.ValidateToolName(toolName); err != nil {
		return "", nil, fmt.Errorf("invalid tool_name: %w", err)
	}
	// Whitespace-only names would also bypass matching.
	if strings.TrimSpace(toolName) == "" {
		return "", nil, fmt.Errorf("tool_name must not be whitespace-only")
	}
	return toolName, toolArgs, nil
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
			return "", nil, fmt.Errorf("invalid toolArgs JSON: %w", jErr)
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

func buildDenyReason(ruleID, reason string) string {
	if ruleID != "" && reason != "" {
		return fmt.Sprintf("Rule '%s': %s", ruleID, reason)
	}
	if reason != "" {
		return reason
	}
	if ruleID != "" {
		return fmt.Sprintf("Blocked by rule '%s'", ruleID)
	}
	return "Blocked"
}

func writeCheckOutput(cmd *cobra.Command, format, decision, ruleID, reason string) error {
	w := cmd.OutOrStdout()
	var output any

	switch format {
	case "claude-code":
		if decision == "block" {
			output = map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny", // Claude Code/Copilot hook protocol value — do not rename,
					"permissionDecisionReason": buildDenyReason(ruleID, reason),
				},
			}
		} else {
			output = map[string]any{}
		}

	case "cursor":
		if decision == "block" {
			output = map[string]any{
				"decision": "block",
				"reason":   buildDenyReason(ruleID, reason),
			}
		} else {
			output = map[string]any{"decision": "allow"}
		}

	case "copilot":
		if decision == "block" {
			output = map[string]any{
				"permissionDecision":       "deny", // Claude Code/Copilot hook protocol value — do not rename,
				"permissionDecisionReason": buildDenyReason(ruleID, reason),
			}
		} else {
			output = map[string]any{}
		}

	case "gemini":
		if decision == "block" {
			output = map[string]any{
				"decision": "block",
				"reason":   buildDenyReason(ruleID, reason),
			}
		} else {
			output = map[string]any{}
		}

	case "opencode":
		if decision == "block" {
			output = map[string]any{
				"allow":  false,
				"reason": buildDenyReason(ruleID, reason),
			}
		} else {
			output = map[string]any{"allow": true}
		}

	case "raw":
		result := map[string]any{"decision": decision}
		if ruleID != "" {
			result["rule_id"] = ruleID
		}
		if reason != "" {
			result["reason"] = reason
		}
		output = result

	default:
		output = map[string]any{"decision": decision}
	}

	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Fprintln(w, string(data))

	// Exit code 1 for deny verdicts — consolidated here so callers don't
	// need to return their own exitError after calling this function.
	if decision == "block" {
		return &exitError{code: 1}
	}
	return nil
}

func writeCheckDeny(cmd *cobra.Command, format, reason string) error {
	return writeCheckOutput(cmd, format, "block", "", reason)
}
