package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

func writeCLITestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	return path
}

func runCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	repoRoot := repoRoot(t)
	binaryPath := filepath.Join(t.TempDir(), "edictum-test")

	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/edictum")
	build.Dir = repoRoot
	var buildOut bytes.Buffer
	build.Stdout = &buildOut
	build.Stderr = &buildOut
	if err := build.Run(); err != nil {
		t.Fatalf("build CLI: %v\noutput:\n%s", err, buildOut.String())
	}

	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = repoRoot
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run CLI: %v\noutput:\n%s", err, out.String())
		}
		exitCode = exitErr.ExitCode()
	}
	return out.String(), exitCode
}

func TestValidate_ValidBundle(t *testing.T) {
	path := writeCLITestFile(t, validateValidBundle)
	out, code := runCLI(t, "validate", path)
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
	path1 := writeCLITestFile(t, validateValidBundle)
	path2 := filepath.Join(t.TempDir(), "rules-v2.yaml")
	if err := os.WriteFile(path2, []byte(validateBundleV2), 0o600); err != nil {
		t.Fatalf("write second file: %v", err)
	}
	out, code := runCLI(t, "validate", path1, path2)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
}

func TestValidate_InvalidAction(t *testing.T) {
	path := writeCLITestFile(t, validateInvalidAction)
	out, code := runCLI(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "action") && !strings.Contains(strings.ToLower(out), "warn") {
		t.Fatalf("expected invalid action message, got:\n%s", out)
	}
}

func TestValidate_DuplicateID(t *testing.T) {
	path := writeCLITestFile(t, validateDuplicateID)
	out, code := runCLI(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(out, "same-id") && !strings.Contains(lower, "duplicate") {
		t.Fatalf("expected duplicate id error, got:\n%s", out)
	}
}

func TestValidate_BadRegex(t *testing.T) {
	path := writeCLITestFile(t, validateBadRegex)
	out, code := runCLI(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "regex") && !strings.Contains(lower, "pattern") {
		t.Fatalf("expected regex error, got:\n%s", out)
	}
}

func TestValidate_YAMLSyntaxError(t *testing.T) {
	path := writeCLITestFile(t, validateYAMLSyntaxError)
	out, code := runCLI(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "yaml") && !strings.Contains(lower, "parse") {
		t.Fatalf("expected YAML parse error, got:\n%s", out)
	}
}

func TestValidate_MissingWhen(t *testing.T) {
	path := writeCLITestFile(t, validateMissingWhen)
	out, code := runCLI(t, "validate", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "when") {
		t.Fatalf("expected missing when error, got:\n%s", out)
	}
}

func TestValidate_NonexistentFile(t *testing.T) {
	out, code := runCLI(t, "validate", "/nonexistent/file.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "no such file") && !strings.Contains(strings.ToLower(out), "not exist") {
		t.Fatalf("expected missing file error, got:\n%s", out)
	}
}

func TestValidate_MixedValidAndInvalid(t *testing.T) {
	validPath := writeCLITestFile(t, validateValidBundle)
	invalidPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(invalidPath, []byte(validateInvalidAction), 0o600); err != nil {
		t.Fatalf("write invalid file: %v", err)
	}
	out, code := runCLI(t, "validate", validPath, invalidPath)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "4 rules") {
		t.Fatalf("expected valid file success to still appear, got:\n%s", out)
	}
}
