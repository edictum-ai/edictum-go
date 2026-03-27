package main

import (
	"encoding/json"
	"fmt"

	"github.com/edictum-ai/edictum-go/guard"
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
		return "", nil, fmt.Errorf("unsupported format %q; supported: claude-code, cursor, copilot, gemini, opencode, raw", format)
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
			output = map[string]any{
				"decision": "deny",
				"reason":   buildDenyReason(contractID, reason),
			}
		} else {
			output = map[string]any{}
		}

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

	default:
		output = map[string]any{"verdict": verdict}
	}

	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Fprintln(w, string(data))

	// Exit code 1 for deny verdicts — consolidated here so callers don't
	// need to return their own exitError after calling this function.
	if verdict == "deny" {
		return &exitError{code: 1}
	}
	return nil
}

func writeCheckDeny(cmd *cobra.Command, format, reason string) error {
	return writeCheckOutput(cmd, format, "deny", "", reason)
}
