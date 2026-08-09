package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type gateWireContract struct {
	pinned       bool
	decisionPath []string
	accepted     map[any]bool
	reasonPaths  [][]string
}

type gateErrorReader struct{}

func (gateErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("injected internal read error")
}

// Host protocols researched 2026-08-09 from primary sources:
//   - Claude Code: https://code.claude.com/docs/en/hooks
//   - Cursor: https://cursor.com/docs/hooks
//   - Copilot: https://docs.github.com/en/copilot/reference/hooks-reference
//   - Gemini: https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md
//   - OpenCode: https://opencode.ai/docs/plugins/
var gateWireContracts = map[string]gateWireContract{
	"claude-code": {
		pinned:       true,
		decisionPath: []string{"hookSpecificOutput", "permissionDecision"},
		accepted:     map[any]bool{"allow": true, "deny": true, "ask": true},
	},
	"cursor": {
		pinned:       true,
		decisionPath: []string{"permission"},
		accepted:     map[any]bool{"allow": true, "deny": true},
		reasonPaths:  [][]string{{"user_message"}, {"agent_message"}},
	},
	"copilot": {
		pinned:       true,
		decisionPath: []string{"permissionDecision"},
		accepted:     map[any]bool{"allow": true, "deny": true, "ask": true},
	},
	"gemini": {
		pinned:       true,
		decisionPath: []string{"decision"},
		accepted:     map[any]bool{"allow": true, "deny": true, "block": true},
	},
	// OpenCode has no JSON decision enum. Edictum's generated plugin owns this
	// bridge value and turns false into the host's documented blocking mechanism: throw.
	"opencode": {
		pinned:       true,
		decisionPath: []string{"allow"},
		accepted:     map[any]bool{false: true},
	},
	// Raw has no target host protocol. Pin it when a named consumer and its
	// primary-source accepted decision set are documented.
	"raw": {pinned: false},
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()
	var got *exitError
	if !errors.As(err, &got) || got.code != want {
		t.Fatalf("exit error = %v, want code %d", err, want)
	}
}

func assertProcessExitCode(t *testing.T, err error, want int) {
	t.Helper()
	if want == 0 {
		if err != nil {
			t.Fatalf("exit error = %v, want success", err)
		}
		return
	}
	assertExitCode(t, err, want)
}

func assertAcceptedWirePayload(t *testing.T, payload []byte, contract gateWireContract) {
	t.Helper()
	if err := acceptedWirePayload(payload, contract); err != nil {
		t.Fatal(err)
	}
}

func acceptedWirePayload(payload []byte, contract gateWireContract) error {
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return err
	}
	if !contract.pinned {
		return nil
	}
	for _, field := range contract.decisionPath {
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("wire decision parent is not an object")
		}
		value, ok = object[field]
		if !ok {
			return errors.New("wire decision field is missing")
		}
	}
	if !contract.accepted[value] {
		return errors.New("emitted wire decision is not accepted by the target host")
	}
	for _, path := range contract.reasonPaths {
		reason, ok := valueAtPath(payload, path).(string)
		if !ok || strings.TrimSpace(reason) == "" {
			return errors.New("wire denial reason is missing")
		}
	}
	return nil
}

func valueAtPath(payload []byte, path []string) any {
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil
	}
	for _, field := range path {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[field]
	}
	return value
}
