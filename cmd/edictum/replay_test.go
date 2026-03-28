package main

import (
	"strings"
	"testing"
)

const replayRulesYAML = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: replay-rules
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env"]
    then:
      action: block
      message: "Sensitive file blocked."
`

func TestReplay_DetectsChanges(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", replayRulesYAML)
	log := writeTempFile(t, "audit.jsonl", `{"tool_name":"read_file","tool_args":{"path":"/app/.env"},"action":"call_allowed"}`+"\n")

	code, out := runEdictum(t, "replay", bundle, "--audit-log", log)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Replayed 1 events, 1 would change") || !strings.Contains(out, "block-env-reads") {
		t.Fatalf("expected replay change summary, got:\n%s", out)
	}
}

func TestReplay_WithOutputFile(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", replayRulesYAML)
	log := writeTempFile(t, "audit.jsonl", `{"tool_name":"read_file","tool_args":{"path":"/app/.env"},"action":"call_allowed"}`+"\n")
	output := writeTempFile(t, "report.jsonl", "")

	code, out := runEdictum(t, "replay", bundle, "--audit-log", log, "--output", output)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Replayed 1 events, 1 would change") {
		t.Fatalf("expected replay summary, got:\n%s", out)
	}
	written := string(mustReadFile(t, output))
	if !strings.Contains(written, `"tool_name":"read_file"`) || !strings.Contains(written, `"changed":true`) {
		t.Fatalf("expected replay report to be written, got:\n%s", written)
	}
}

func TestReplay_NoChanges(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", replayRulesYAML)
	log := writeTempFile(t, "audit.jsonl", `{"tool_name":"read_file","tool_args":{"path":"README.md"},"action":"call_allowed"}`+"\n")

	code, out := runEdictum(t, "replay", bundle, "--audit-log", log)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Replayed 1 events, 0 would change") {
		t.Fatalf("expected no-change summary, got:\n%s", out)
	}
}

func TestReplay_EmptyLog(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", replayRulesYAML)
	log := writeTempFile(t, "audit.jsonl", "\n")

	code, out := runEdictum(t, "replay", bundle, "--audit-log", log)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Replayed 0 events, 0 would change") {
		t.Fatalf("expected empty replay summary, got:\n%s", out)
	}
}

func TestReplay_InvalidRules(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", invalidYAMLSyntax)
	log := writeTempFile(t, "audit.jsonl", `{"tool_name":"read_file","tool_args":{"path":"README.md"},"action":"call_allowed"}`+"\n")

	code, out := runEdictum(t, "replay", bundle, "--audit-log", log)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (go run wrapper for CLI exit 2)\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "building guard") || !strings.Contains(out, "exit status 2") {
		t.Fatalf("expected rules error, got:\n%s", out)
	}
}

func TestReplay_MalformedLogLine(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", replayRulesYAML)
	log := writeTempFile(t, "audit.jsonl", "this is not json\n"+`{"tool_name":"read_file","tool_args":{"path":"README.md"},"action":"call_allowed"}`+"\n")

	code, out := runEdictum(t, "replay", bundle, "--audit-log", log)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Replayed 1 events, 0 would change") {
		t.Fatalf("expected malformed line to be skipped, got:\n%s", out)
	}
}
