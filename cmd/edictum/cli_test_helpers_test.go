package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

const validBundleYAML = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle
  description: "Valid test bundle."
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
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets]

  - id: bash-safety
    type: pre
    tool: bash
    when:
      args.command:
        matches: '\\brm\\s+-rf\\b'
    then:
      action: block
      message: "Destructive command blocked."
      tags: [safety]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 50
    then:
      action: block
      message: "Session limit reached."
      tags: [rate-limit]
`

const bundleV2YAML = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle-v2
  description: "Updated bundle."
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
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets]

  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      principal.ticket_ref:
        exists: false
    then:
      action: block
      message: "Ticket required."
      tags: [compliance]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 100
    then:
      action: block
      message: "Session limit reached."
      tags: [rate-limit]
`

const invalidYAMLSyntax = `apiVersion: edictum/v1
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

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file %s: %v", name, err)
	}
	return path
}

func runEdictum(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"run", "./cmd/edictum"}, args...)...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		return 0, output
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), output
	}
	return -1, output
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return data
}
