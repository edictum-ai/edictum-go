package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

const jsonValidBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle
  description: Valid test bundle.
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env", ".secret"]
    then:
      action: block
      message: "Sensitive file '{args.path}' blocked."
  - id: bash-safety
    type: pre
    tool: bash
    when:
      "args.command":
        matches: "\\brm\\s+-rf\\b"
    then:
      action: block
      message: "Destructive command blocked."
  - id: pii-check
    type: post
    tool: "*"
    when:
      "output.text":
        matches: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    then:
      action: warn
      message: "PII detected."
  - id: session-cap
    type: session
    limits:
      max_tool_calls: 50
    then:
      action: block
      message: "Session limit reached."
`

const jsonBundleV2 = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle-v2
  description: Updated bundle.
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env", ".secret", ".pem"]
    then:
      action: block
      message: "Sensitive file '{args.path}' blocked."
  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      "principal.ticket_ref":
        exists: false
    then:
      action: block
      message: "Ticket required."
  - id: pii-check
    type: post
    tool: "*"
    when:
      "output.text":
        matches: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    then:
      action: warn
      message: "PII detected."
  - id: session-cap
    type: session
    limits:
      max_tool_calls: 100
    then:
      action: block
      message: "Session limit reached."
`

const jsonObserveBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: candidate-bundle
  description: Observe alongside candidate.
defaults:
  mode: enforce
observe_alongside: true
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env", ".secret", ".pem"]
    then:
      action: block
      message: "Candidate sensitive file rule."
`

const jsonInvalidBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bad-action
defaults:
  mode: enforce
rules:
  - id: bad-rule
    type: pre
    tool: bash
    when:
      "args.command":
        contains: "rm"
    then:
      action: warn
      message: "Wrong action for pre."
`

func mustJSONMap(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal json %q: %v", buf.String(), err)
	}
	return out
}

func mustMap(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	mapped, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected %s to be map[string]any, got %T", label, value)
	}
	return mapped
}

func mustSlice(t *testing.T, value any, label string) []any {
	t.Helper()
	slice, ok := value.([]any)
	if !ok {
		t.Fatalf("expected %s to be []any, got %T", label, value)
	}
	return slice
}
