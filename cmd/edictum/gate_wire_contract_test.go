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

	tests := []struct {
		format   string
		wantExit int
	}{
		// Measured on Claude Code 2.1.226 on 2026-08-09: exit 2 blocks and preserves permissionDecisionReason.
		{"claude-code", 2},
		// https://cursor.com/docs/hooks (fetched 2026-08-09) only promises JSON processing on exit 0;
		// evidence that exit 2 preserves user_message and agent_message is still required.
		{"cursor", 0},
		// https://docs.github.com/en/copilot/reference/hooks-reference (fetched 2026-08-09):
		// PreToolUse exit 2 denies and merges stdout JSON with the deny decision.
		{"copilot", 2},
		// Gemini's generated wrapper converts this internal exit 1 to host exit 2 while preserving stdout JSON.
		{"gemini", 1},
		// https://opencode.ai/docs/plugins/ (fetched 2026-08-09): the generated plugin blocks by throwing on allow:false.
		{"opencode", 0},
		// Raw has no host protocol; preserve its generic Unix-style policy-deny exit.
		{"raw", 1},
	}

	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			cmd := newGateCheckCmd()
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetIn(strings.NewReader(gateWireBlockInput(test.format)))

			err := runGateCheck(cmd, test.format, rules, false)
			assertProcessExitCode(t, err, test.wantExit)
			assertAcceptedWirePayload(t, stdout.Bytes(), gateWireContracts[test.format])
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
