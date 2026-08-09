package main

import (
	"encoding/json"
	"errors"
	"testing"
)

type gateWireContract struct {
	pinned       bool
	decisionPath []string
	accepted     map[any]bool
}

type gateErrorReader struct{}

func (gateErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("injected internal read error")
}

// Host protocols researched 2026-08-09 from primary sources:
//   - Claude Code: https://code.claude.com/docs/en/hooks
//   - Copilot: https://docs.github.com/en/copilot/reference/hooks-reference
//   - OpenCode: https://opencode.ai/docs/plugins/
var gateWireContracts = map[string]gateWireContract{
	"claude-code": {
		pinned:       true,
		decisionPath: []string{"hookSpecificOutput", "permissionDecision"},
		accepted:     map[any]bool{"allow": true, "deny": true, "ask": true},
	},
	"copilot": {
		pinned:       true,
		decisionPath: []string{"permissionDecision"},
		accepted:     map[any]bool{"allow": true, "deny": true, "ask": true},
	},
	// OpenCode has no JSON decision enum. Edictum's generated plugin owns this
	// bridge value and turns false into the host's documented blocking mechanism: throw.
	"opencode": {
		pinned:       true,
		decisionPath: []string{"allow"},
		accepted:     map[any]bool{false: true, true: true},
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
	return nil
}
