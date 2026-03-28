package main

import (
	"strings"
	"testing"
)

const validateValidBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret"]
    then:
      action: block
      message: "Sensitive file blocked."

  - id: bash-safety
    type: pre
    tool: bash
    when:
      args.command:
        matches: '\brm\s+-rf\b'
    then:
      action: block
      message: "Destructive command blocked."

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\b\d{3}-\d{2}-\d{4}\b'
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

const validateBundleV2 = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle-v2
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", ".pem"]
    then:
      action: block
      message: "Sensitive file blocked."

  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      principal.ticket_ref:
        exists: false
    then:
      action: block
      message: "Ticket required."

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\b\d{3}-\d{2}-\d{4}\b'
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

const validateInvalidAction = `apiVersion: edictum/v1
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
      args.command:
        contains: "rm"
    then:
      action: warn
      message: "Wrong action for pre."
`

const validateDuplicateID = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: dupe-ids
defaults:
  mode: enforce
rules:
  - id: same-id
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm"
    then:
      action: block
      message: "First rule."

  - id: same-id
    type: pre
    tool: read_file
    when:
      args.path:
        contains: ".env"
    then:
      action: block
      message: "Duplicate."
`

const validateBadRegex = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bad-regex
defaults:
  mode: enforce
rules:
  - id: bad-regex-rule
    type: pre
    tool: bash
    when:
      args.command:
        matches: "[invalid(regex"
    then:
      action: block
      message: "Bad regex."
`

const validateYAMLSyntaxError = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: broken
defaults:
  mode: enforce
rules:
  - id: rule1
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm"
    then:
      action: block
      message: "Broken YAML."
`

const validateMissingWhen = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: no-when
defaults:
  mode: enforce
rules:
  - id: no-when-rule
    type: pre
    tool: bash
    then:
      action: block
      message: "Missing when."
`

func TestValidate_ValidBundle(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", validateValidBundle)
	code, out := runEdictum(t, "validate", path)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "4 rules") {
		t.Fatalf("expected rule count in output, got:\n%s", out)
	}
	for _, want := range []string{"pre", "post", "session"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestValidate_MultipleValidFiles(t *testing.T) {
	path1 := writeTempFile(t, "rules.yaml", validateValidBundle)
	path2 := writeTempFile(t, "rules-v2.yaml", validateBundleV2)
	code, out := runEdictum(t, "validate", path1, path2)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
}

func TestValidate_InvalidAction(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", validateInvalidAction)
	code, out := runEdictum(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "action") && !strings.Contains(strings.ToLower(out), "warn") {
		t.Fatalf("expected invalid action message, got:\n%s", out)
	}
}

func TestValidate_DuplicateID(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", validateDuplicateID)
	code, out := runEdictum(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(out, "same-id") && !strings.Contains(lower, "duplicate") {
		t.Fatalf("expected duplicate id error, got:\n%s", out)
	}
}

func TestValidate_BadRegex(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", validateBadRegex)
	code, out := runEdictum(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "regex") && !strings.Contains(lower, "pattern") {
		t.Fatalf("expected regex error, got:\n%s", out)
	}
}

func TestValidate_YAMLSyntaxError(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", validateYAMLSyntaxError)
	code, out := runEdictum(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "yaml") && !strings.Contains(lower, "parse") {
		t.Fatalf("expected YAML parse error, got:\n%s", out)
	}
}

func TestValidate_MissingWhen(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", validateMissingWhen)
	code, out := runEdictum(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "when") {
		t.Fatalf("expected missing when error, got:\n%s", out)
	}
}

func TestValidate_NonexistentFile(t *testing.T) {
	code, out := runEdictum(t, "validate", "/nonexistent/file.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "no such file") && !strings.Contains(strings.ToLower(out), "not exist") {
		t.Fatalf("expected missing file error, got:\n%s", out)
	}
}

func TestValidate_MixedValidAndInvalid(t *testing.T) {
	validPath := writeTempFile(t, "rules.yaml", validateValidBundle)
	invalidPath := writeTempFile(t, "bad.yaml", validateInvalidAction)
	code, out := runEdictum(t, "validate", validPath, invalidPath)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "4 rules") {
		t.Fatalf("expected valid file success to still appear, got:\n%s", out)
	}
}
