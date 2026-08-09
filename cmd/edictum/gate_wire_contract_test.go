package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityGatePolicyBlockWireContracts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rules := writeTestBundle(t)

	for format, contract := range gateWireContracts {
		t.Run(format, func(t *testing.T) {
			cmd := newGateCheckCmd()
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetIn(strings.NewReader(gateWireBlockInput(format)))

			err := runGateCheck(cmd, format, rules, false)
			wantExit := 0
			if format == "gemini" || format == "raw" {
				wantExit = 1
			}
			assertProcessExitCode(t, err, wantExit)
			assertAcceptedWirePayload(t, stdout.Bytes(), contract)
		})
	}
}

func TestSecurityGateFailureWireContracts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	validRules := writeTestBundle(t)
	invalidRules := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(invalidRules, []byte("rules: ["), 0o600); err != nil {
		t.Fatal(err)
	}

	failures := []struct {
		name        string
		stdin       string
		rules       string
		readerError bool
	}{
		{"no_rules_configured", "valid", "", false},
		{"rules_path_missing", "valid", filepath.Join(t.TempDir(), "missing.yaml"), false},
		{"rules_load_failure", "valid", invalidRules, false},
		{"malformed_stdin", "{", validRules, false},
		{"internal_error", "valid", validRules, true},
	}

	for format, contract := range gateWireContracts {
		for _, failure := range failures {
			t.Run(format+"/"+failure.name, func(t *testing.T) {
				cmd := newGateCheckCmd()
				var stdout bytes.Buffer
				cmd.SetOut(&stdout)
				if failure.readerError {
					cmd.SetIn(gateErrorReader{})
				} else {
					cmd.SetIn(strings.NewReader(gateWireInput(format, failure.stdin)))
				}

				err := runGateCheck(cmd, format, failure.rules, false)
				assertExitCode(t, err, 2)
				assertAcceptedWirePayload(t, stdout.Bytes(), contract)
			})
		}
	}
}

func TestGateWireContractRejectsInternalBlock(t *testing.T) {
	for _, format := range []string{"claude-code", "copilot", "cursor"} {
		t.Run(format, func(t *testing.T) {
			payload := []byte(`{"permissionDecision":"block"}`)
			switch format {
			case "claude-code":
				payload = []byte(`{"hookSpecificOutput":{"permissionDecision":"block"}}`)
			case "cursor":
				payload = []byte(`{"permission":"block"}`)
			}
			if err := acceptedWirePayload(payload, gateWireContracts[format]); err == nil {
				t.Fatal("internal decision value block must be rejected at this wire boundary")
			}
		})
	}
}

func gateWireInput(format, input string) string {
	if input != "valid" {
		return input
	}
	switch format {
	case "copilot":
		return `{"toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`
	case "opencode":
		return `{"tool":"bash","args":{"command":"echo ok"}}`
	default:
		return `{"tool_name":"Bash","tool_input":{"command":"echo ok"}}`
	}
}

func gateWireBlockInput(format string) string {
	switch format {
	case "copilot":
		return `{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /tmp/blocked\"}"}`
	case "opencode":
		return `{"tool":"bash","args":{"command":"rm -rf /tmp/blocked"}}`
	default:
		return `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/blocked"}}`
	}
}
