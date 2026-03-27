package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Minimal contract bundle for security tests. Denies rm -rf commands.
const testContractBundle = `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: deny-rm-rf
    type: pre
    tool: Bash
    when:
      command:
        contains: "rm -rf"
    action: deny
    message: "rm -rf is not allowed"
`

// writeTestBundle writes a minimal contract bundle to a temp directory
// and returns its path.
func writeTestBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "contracts.yaml")
	if err := os.WriteFile(path, []byte(testContractBundle), 0o600); err != nil {
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

	// Use raw format with explicit contracts path.
	cmd.SetArgs([]string{"--format", "raw", "--contracts", bundlePath})
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
			cmd.SetArgs([]string{"--format", "raw", "--contracts", bundlePath})

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
	cmd.SetArgs([]string{"--format", "nonexistent-format", "--contracts", bundlePath})

	// Must not panic. Unknown format should be rejected with an error.
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

func TestSecurityGateCheckToolNameWithControlChars(t *testing.T) {
	bundlePath := writeTestBundle(t)

	// Tool names with null bytes and control characters.
	inputs := []string{
		`{"tool_name": "Bash\u0000Inject", "tool_input": {"command": "echo hello"}}`,
		`{"tool_name": "\t\n\r", "tool_input": {}}`,
		`{"tool_name": "", "tool_input": {"command": "echo hello"}}`,
	}

	for i, input := range inputs {
		t.Run(strings.ReplaceAll(input[:min(30, len(input))], "\n", "\\n"), func(t *testing.T) {
			t.Helper()
			cmd := newGateCheckCmd()
			cmd.SetIn(strings.NewReader(input))
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stdout)
			cmd.SetArgs([]string{"--format", "raw", "--contracts", bundlePath})

			// Must not panic.
			err := cmd.Execute()
			_ = err // Any non-panic result is acceptable.
			_ = i
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
