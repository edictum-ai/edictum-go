package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Minimal rule bundle for security tests. Denies rm -rf commands.
const testRuleset = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-rules
defaults:
  mode: enforce
rules:
  - id: deny-rm-rf
    type: pre
    tool: Bash
    when:
      bash_command:
        contains: "rm -rf"
    then:
      action: block
      message: "rm -rf is not allowed"
`

// writeTestBundle writes a minimal rule bundle to a temp directory
// and returns its path.
func writeTestBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(testRuleset), 0o600); err != nil {
		t.Fatalf("writing test bundle: %v", err)
	}
	return path
}

func TestSecurityGateCheckEmptyStdin(t *testing.T) {
	bundlePath := writeTestBundle(t)
	cmd := newGateCheckCmd()
	cmd.SetIn(strings.NewReader(""))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	// Use raw format with explicit rules path.
	cmd.SetArgs([]string{"--format", "raw", "--rules", bundlePath})
	err := cmd.Execute()

	// Must not panic. Must return an error (empty stdin is not valid JSON).
	if err == nil {
		t.Fatal("expected error for empty stdin, got nil")
	}
}

func TestSecurityGateCheckMalformedStdin(t *testing.T) {
	bundlePath := writeTestBundle(t)

	inputs := []struct {
		name  string
		input string
	}{
		{"garbage", "not json at all"},
		{"truncated_json", `{"tool_name": "Bash"`},
		{"array_instead_of_object", `[1, 2, 3]`},
		{"null_literal", "null"},
		{"nested_garbage", `{"tool_name": {"nested": "object"}}`},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			cmd := newGateCheckCmd()
			cmd.SetIn(strings.NewReader(tc.input))
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stdout)
			cmd.SetArgs([]string{"--format", "raw", "--rules", bundlePath})

			// Must not panic.
			_ = cmd.Execute()
		})
	}
}

func TestSecurityGateCheckUnknownFormat(t *testing.T) {
	bundlePath := writeTestBundle(t)
	input := `{"tool_name": "Bash", "tool_input": {"command": "echo hello"}}`

	cmd := newGateCheckCmd()
	cmd.SetIn(strings.NewReader(input))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--format", "nonexistent-format", "--rules", bundlePath})

	// Must not panic. Unknown format should be rejected with an error.
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

func TestSecurityGateCheckToolNameWithControlChars(t *testing.T) {
	bundlePath := writeTestBundle(t)

	// Tool names with null bytes and control characters must not panic and must not allow.
	inputs := []struct {
		name  string
		input string
	}{
		{"null_byte", `{"tool_name": "Bash\u0000Inject", "tool_input": {"command": "echo hello"}}`},
		{"control_chars", `{"tool_name": "\t\n\r", "tool_input": {}}`},
		{"empty_tool_name", `{"tool_name": "", "tool_input": {"command": "rm -rf /"}}`},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			cmd := newGateCheckCmd()
			cmd.SetIn(strings.NewReader(tc.input))
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stdout)
			cmd.SetArgs([]string{"--format", "raw", "--rules", bundlePath})

			// Must not panic, and must not allow.
			err := cmd.Execute()
			if err == nil {
				// Check stdout — if decision is "allow", that's a bypass.
				if strings.Contains(stdout.String(), `"allow"`) {
					t.Fatal("empty/malformed tool_name must not produce allow decision")
				}
			}
		})
	}
}

func TestSecurityUnsupportedAssistantInstall(t *testing.T) {
	_, err := installAssistant("nonexistent-assistant")
	if err == nil {
		t.Fatal("expected error for unsupported assistant, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported assistant") {
		t.Fatalf("expected 'unsupported assistant' error, got: %v", err)
	}
}

func TestSecurityUnsupportedAssistantUninstall(t *testing.T) {
	_, err := uninstallAssistant("nonexistent-assistant")
	if err == nil {
		t.Fatal("expected error for unsupported assistant, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported assistant") {
		t.Fatalf("expected 'unsupported assistant' error, got: %v", err)
	}
}
