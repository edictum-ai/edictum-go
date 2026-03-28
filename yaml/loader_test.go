package yaml

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validBundle = `apiVersion: edictum/v2
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: no-rm
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "rm -rf"
    then:
      action: block
      message: "Cannot run rm -rf"
  - id: redact-keys
    type: post
    tool: Bash
    when:
      "output.text":
        matches: "sk-[a-zA-Z0-9]+"
    then:
      action: redact
      message: "Sensitive key detected"
`

// Cat 3.1 — Bundle size limit 1MB
func TestLoadBundleString_SizeLimit(t *testing.T) {
	huge := "apiVersion: edictum/v2\n" + strings.Repeat("x", MaxBundleSize+1)
	_, _, err := LoadBundleString(huge)
	if err == nil {
		t.Fatal("expected error for oversized bundle")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.1 — File-based size limit
func TestLoadBundle_FileSizeLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(p, make([]byte, MaxBundleSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadBundle(p)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Basic schema validation: apiVersion
func TestLoadBundleString_MissingApiVersion(t *testing.T) {
	_, _, err := LoadBundleString("kind: Ruleset\nrules: []\n")
	if err == nil {
		t.Fatal("expected error for missing apiVersion")
	}
	if !strings.Contains(err.Error(), "apiVersion") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Basic schema validation: kind
func TestLoadBundleString_MissingKind(t *testing.T) {
	_, _, err := LoadBundleString("apiVersion: edictum/v2\nrules: []\n")
	if err == nil {
		t.Fatal("expected error for missing kind")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Reject non-mapping YAML
func TestLoadBundleString_NonMapping(t *testing.T) {
	_, _, err := LoadBundleString("- item1\n- item2\n")
	if err == nil {
		t.Fatal("expected error for non-mapping document")
	}
	if !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — defaults.mode validation
func TestLoadBundleString_InvalidMode(t *testing.T) {
	y := "apiVersion: edictum/v2\nkind: Ruleset\ndefaults:\n  mode: shadow\nrules: []\n"
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "defaults.mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Rule missing id
func TestLoadBundleString_ContractMissingID(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - type: pre
    tool: Bash
    when:
      "args.command":
        contains: "rm"
    then:
      action: block
      message: "Denied"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for missing rule id")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "id is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Rule invalid type
func TestLoadBundleString_ContractInvalidType(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: bad
    type: invalid
    tool: Bash
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for invalid rule type")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Rule missing tool for non-session type
func TestLoadBundleString_ContractMissingTool(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: no-tool
    type: pre
    when:
      "args.command":
        contains: "rm"
    then:
      action: block
      message: "Denied"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for missing tool")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "tool is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Session rules do not require tool
func TestLoadBundleString_SessionNoTool(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: sess-limit
    type: session
    limits:
      max_tool_calls: 10
    then:
      action: block
      message: "limit hit"
`
	data, _, err := LoadBundleString(y)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["apiVersion"] != "edictum/v2" {
		t.Fatal("wrong apiVersion")
	}
}

// Cat 3.3 — Unique rule ID
func TestLoadBundleString_DuplicateID(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: same-id
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "rm"
    then:
      action: block
      message: "Denied"
  - id: same-id
    type: post
    tool: Bash
    when:
      "output.text":
        contains: "secret"
    then:
      action: warn
      message: "Warn"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for duplicate id")
	}
	if !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.4 — Regex pre-compilation: invalid regex at load time
func TestLoadBundleString_InvalidRegex(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: bad-regex
    type: post
    tool: Bash
    when:
      "output.text":
        matches: "[invalid"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.4 — Invalid regex in matches_any
func TestLoadBundleString_InvalidRegexMatchesAny(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: bad-regex-any
    type: post
    tool: Bash
    when:
      "output.text":
        matches_any:
          - "valid.*"
          - "[broken"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for invalid regex in matches_any")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.4 — Regex inside boolean combinator
func TestLoadBundleString_InvalidRegexNested(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: nested-bad
    type: post
    tool: Bash
    when:
      all:
        - "output.text":
            matches: "[broken"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for invalid regex in nested expr")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.5 — Pre-rule output.text rejection
func TestLoadBundleString_PreOutputTextRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: pre-output
    type: pre
    tool: Bash
    when:
      "output.text":
        contains: "secret"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for output.text in pre rule")
	}
	if !strings.Contains(err.Error(), "output.text") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.5 — output.text nested in boolean combinator for pre
func TestLoadBundleString_PreOutputTextNestedRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: pre-nested
    type: pre
    tool: Bash
    when:
      any:
        - "output.text":
            contains: "secret"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for output.text nested in pre rule")
	}
	if !strings.Contains(err.Error(), "output.text") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.5 — output.text in post rule is allowed
func TestLoadBundleString_PostOutputTextAllowed(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: post-ok
    type: post
    tool: Bash
    when:
      "output.text":
        contains: "secret"
`
	_, _, err := LoadBundleString(y)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: not_within without within (no primary constraint)
func TestLoadBundleString_SandboxNotWithinRequiresWithin(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: sb1
    type: sandbox
    tool: Bash
    not_within:
      - /tmp/evil
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for not_within without within")
	}
	if !strings.Contains(err.Error(), "schema validation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: not_allows without allows (no primary constraint)
func TestLoadBundleString_SandboxNotAllowsRequiresAllows(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: sb2
    type: sandbox
    tool: Bash
    not_allows:
      domains:
        - evil.com
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for not_allows without allows")
	}
	if !strings.Contains(err.Error(), "schema validation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: not_allows.domains requires allows.domains
func TestLoadBundleString_SandboxNotAllowsDomainsRequiresAllowsDomains(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: sb3
    type: sandbox
    tool: Bash
    allows:
      commands:
        - ls
    not_allows:
      domains:
        - evil.com
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for not_allows.domains without allows.domains")
	}
	if !strings.Contains(err.Error(), "not_allows.domains requires allows.domains") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: not_allows.commands is rejected (only domains valid)
func TestLoadBundleString_SandboxNotAllowsCommandsRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: sb4
    type: sandbox
    tool: Bash
    allows:
      commands:
        - ls
    not_allows:
      commands:
        - rm
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for not_allows.commands")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "not_allows") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: non-string entries in within are rejected
func TestLoadBundleString_SandboxNonStringWithinRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: bad-within
    type: sandbox
    tool: read_file
    within:
      - 42
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for non-string within entry")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "within.0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: valid with both within and not_within
func TestLoadBundleString_SandboxValidWithBothWithin(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: sb-ok
    type: sandbox
    tool: Bash
    within:
      - /home/user
    not_within:
      - /home/user/.ssh
`
	_, _, err := LoadBundleString(y)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: empty sandbox (no constraints) is rejected
func TestLoadBundleString_SandboxEmptyRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: empty-sb
    type: sandbox
    tool: Bash
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for sandbox with no constraints")
	}
	if !strings.Contains(err.Error(), "schema validation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: within: [] (empty list) is rejected
func TestLoadBundleString_SandboxEmptyWithinRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: empty-within
    type: sandbox
    tool: read_file
    within: []
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for sandbox with empty within list")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "within") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: allows: {} (empty map) is rejected
func TestLoadBundleString_SandboxEmptyAllowsRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: empty-allows
    type: sandbox
    tool: Bash
    allows: {}
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for sandbox with empty allows")
	}
	if !strings.Contains(err.Error(), "must have at least one primary constraint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.7 — SHA256 policy_version
func TestLoadBundleString_SHA256Hash(t *testing.T) {
	_, hash, err := LoadBundleString(validBundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sum := sha256.Sum256([]byte(validBundle))
	want := hex.EncodeToString(sum[:])
	if hash.Hex != want {
		t.Fatalf("hash mismatch: got %s, want %s", hash.Hex, want)
	}
	if hash.String() != want {
		t.Fatalf("String() mismatch: got %s, want %s", hash.String(), want)
	}
}

// Valid bundle loads successfully
func TestLoadBundleString_ValidBundle(t *testing.T) {
	data, hash, err := LoadBundleString(validBundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["apiVersion"] != "edictum/v2" {
		t.Fatal("wrong apiVersion")
	}
	if data["kind"] != "Ruleset" {
		t.Fatal("wrong kind")
	}
	rules, ok := data["rules"].([]any)
	if !ok || len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %v", data["rules"])
	}
	if hash.Hex == "" {
		t.Fatal("hash should not be empty")
	}
}

// File-based loading
func TestLoadBundle_ValidFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(p, []byte(validBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	data, hash, err := LoadBundle(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["apiVersion"] != "edictum/v2" {
		t.Fatal("wrong apiVersion")
	}
	if hash.Hex == "" {
		t.Fatal("hash should not be empty")
	}
}

// File not found
func TestLoadBundle_FileNotFound(t *testing.T) {
	_, _, err := LoadBundle("/nonexistent/path/bundle.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// Cat 3.6 — Sandbox: non-string entries in allows.commands are rejected
func TestLoadBundleString_SandboxNonStringCommandsRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: bad-cmds
    type: sandbox
    tool: Bash
    allows:
      commands:
        - 42
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for non-string allows.commands entry")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "allows.commands.0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: non-string entries in allows.domains are rejected
func TestLoadBundleString_SandboxNonStringDomainsRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: bad-doms
    type: sandbox
    tool: fetch
    allows:
      domains:
        - true
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for non-string allows.domains entry")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "allows.domains.0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: non-string entries in not_allows.domains are rejected
func TestLoadBundleString_SandboxNonStringNotAllowsDomainsRejected(t *testing.T) {
	y := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: bad-not-allows-doms
    type: sandbox
    tool: fetch
    allows:
      domains:
        - "*.example.com"
    not_allows:
      domains:
        - 42
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for non-string not_allows.domains entry")
	}
	if !strings.Contains(err.Error(), "schema validation failed") || !strings.Contains(err.Error(), "not_allows.domains.0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecurity_ShadowInjection(t *testing.T) {
	// A user-supplied YAML bundle must not be able to set _observe: true
	// on a rule. This internal key is reserved for observe_alongside
	// composition — if accepted, it silently downgrades enforce→observe.
	bundle := `
apiVersion: edictum/v2
kind: Ruleset
defaults:
  mode: enforce
rules:
  - id: injected
    type: pre
    tool: "*"
    _observe: true
    when:
      args.command:
        contains: "rm"
    then:
      message: "Blocked"
`
	_, _, err := LoadBundleString(bundle)
	if err == nil {
		t.Fatal("expected error: _observe key should be rejected in user YAML")
	}
}
