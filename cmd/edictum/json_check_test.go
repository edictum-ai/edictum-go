package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckJSON_Allowed(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    `{"path":"safe.txt"}`,
		environment: "production",
		jsonOutput:  true,
	})
	if err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["tool"] != "read_file" || parsed["decision"] != "allow" || parsed["environment"] != "production" {
		t.Fatalf("unexpected payload: %#v", parsed)
	}
	args := mustMap(t, parsed["args"], "args")
	if args["path"] != "safe.txt" {
		t.Fatalf("args: got %#v", args)
	}
}

func TestCheckJSON_Blocked(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    `{"path":"/app/.env"}`,
		environment: "production",
		jsonOutput:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("expected exit 1, got %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["decision"] != "block" || parsed["rule_id"] != "block-env-reads" {
		t.Fatalf("unexpected payload: %#v", parsed)
	}
	if parsed["reason"] == nil || parsed["reason"] == "" {
		t.Fatalf("reason should be present: %#v", parsed["reason"])
	}
}

func TestCheckJSON_CustomEnvironment(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    `{"path":"safe.txt"}`,
		environment: "staging",
		jsonOutput:  true,
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["environment"] != "staging" {
		t.Fatalf("environment: got %#v, want staging", parsed["environment"])
	}
}

func TestCheckJSON_InvalidArgs(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    "not-json",
		environment: "production",
		jsonOutput:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "exit 2") {
		t.Fatalf("expected exit 2, got %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if _, ok := parsed["error"]; !ok {
		t.Fatalf("expected error payload, got %#v", parsed)
	}
}

func TestCheckJSON_Parseable(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	_ = runCheck(cmd, []string{path}, checkArgs{
		toolName:    "bash",
		argsJSON:    `{"command":"rm -rf /"}`,
		environment: "production",
		jsonOutput:  true,
	})

	if strings.Contains(stdout.String(), "[red") || strings.Contains(stdout.String(), "[green") || strings.Contains(stdout.String(), "[bold") {
		t.Fatalf("unexpected rich markup in %q", stdout.String())
	}
	_ = mustJSONMap(t, &stdout)
}

func TestCheckJSON_RequiredKeys(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "send_email",
		argsJSON:    `{"to":"x@y.com"}`,
		environment: "production",
		jsonOutput:  true,
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	for _, key := range []string{"tool", "args", "decision", "rules_evaluated", "environment"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("missing key %q in %#v", key, parsed)
		}
	}
}
