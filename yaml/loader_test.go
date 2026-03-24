package yaml

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validBundle = `apiVersion: edictum/v1
kind: ContractBundle
defaults:
  mode: enforce
contracts:
  - id: no-rm
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "rm -rf"
    action: deny
    message: "Cannot run rm -rf"
  - id: redact-keys
    type: post
    tool: Bash
    when:
      "output.text":
        matches: "sk-[a-zA-Z0-9]+"
    action: redact
`

// Cat 3.1 — Bundle size limit 1MB
func TestLoadBundleString_SizeLimit(t *testing.T) {
	huge := "apiVersion: edictum/v1\n" + strings.Repeat("x", MaxBundleSize+1)
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
	_, _, err := LoadBundleString("kind: ContractBundle\ncontracts: []\n")
	if err == nil {
		t.Fatal("expected error for missing apiVersion")
	}
	if !strings.Contains(err.Error(), "apiVersion") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Basic schema validation: kind
func TestLoadBundleString_MissingKind(t *testing.T) {
	_, _, err := LoadBundleString("apiVersion: edictum/v1\ncontracts: []\n")
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
	y := "apiVersion: edictum/v1\nkind: ContractBundle\ndefaults:\n  mode: shadow\ncontracts: []\n"
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "defaults.mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Contract missing id
func TestLoadBundleString_ContractMissingID(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - type: pre
    tool: Bash
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for missing contract id")
	}
	if !strings.Contains(err.Error(), "missing required field 'id'") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Contract invalid type
func TestLoadBundleString_ContractInvalidType(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: bad
    type: invalid
    tool: Bash
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for invalid contract type")
	}
	if !strings.Contains(err.Error(), "invalid type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Contract missing tool for non-session type
func TestLoadBundleString_ContractMissingTool(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: no-tool
    type: pre
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for missing tool")
	}
	if !strings.Contains(err.Error(), "missing required field 'tool'") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.2 — Session contracts do not require tool
func TestLoadBundleString_SessionNoTool(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: sess-limit
    type: session
`
	data, _, err := LoadBundleString(y)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["apiVersion"] != "edictum/v1" {
		t.Fatal("wrong apiVersion")
	}
}

// Cat 3.3 — Unique contract ID
func TestLoadBundleString_DuplicateID(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: same-id
    type: pre
    tool: Bash
  - id: same-id
    type: post
    tool: Bash
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for duplicate id")
	}
	if !strings.Contains(err.Error(), "duplicate contract id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.4 — Regex pre-compilation: invalid regex at load time
func TestLoadBundleString_InvalidRegex(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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

// Cat 3.5 — Pre-contract output.text rejection
func TestLoadBundleString_PreOutputTextRejected(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: pre-output
    type: pre
    tool: Bash
    when:
      "output.text":
        contains: "secret"
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for output.text in pre contract")
	}
	if !strings.Contains(err.Error(), "output.text") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.5 — output.text nested in boolean combinator for pre
func TestLoadBundleString_PreOutputTextNestedRejected(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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
		t.Fatal("expected error for output.text nested in pre contract")
	}
	if !strings.Contains(err.Error(), "output.text") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.5 — output.text in post contract is allowed
func TestLoadBundleString_PostOutputTextAllowed(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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

// Cat 3.6 — Sandbox: not_within requires within
func TestLoadBundleString_SandboxNotWithinRequiresWithin(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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
	if !strings.Contains(err.Error(), "not_within requires within") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: not_allows requires allows
func TestLoadBundleString_SandboxNotAllowsRequiresAllows(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: sb2
    type: sandbox
    tool: Bash
    not_allows:
      commands:
        - rm
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for not_allows without allows")
	}
	if !strings.Contains(err.Error(), "not_allows requires allows") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Cat 3.6 — Sandbox: not_allows.domains requires allows.domains
func TestLoadBundleString_SandboxNotAllowsDomainsRequiresAllowsDomains(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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

// Cat 3.6 — Sandbox: valid with both within and not_within
func TestLoadBundleString_SandboxValidWithBothWithin(t *testing.T) {
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
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
	y := `apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - id: empty-sb
    type: sandbox
    tool: Bash
`
	_, _, err := LoadBundleString(y)
	if err == nil {
		t.Fatal("expected error for sandbox with no constraints")
	}
	if !strings.Contains(err.Error(), "must have at least one constraint") {
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
	if data["apiVersion"] != "edictum/v1" {
		t.Fatal("wrong apiVersion")
	}
	if data["kind"] != "ContractBundle" {
		t.Fatal("wrong kind")
	}
	contracts, ok := data["contracts"].([]any)
	if !ok || len(contracts) != 2 {
		t.Fatalf("expected 2 contracts, got %v", data["contracts"])
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
	if data["apiVersion"] != "edictum/v1" {
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

func TestSecurity_ShadowInjection(t *testing.T) {
	// A user-supplied YAML bundle must not be able to set _observe: true
	// on a contract. This internal key is reserved for observe_alongside
	// composition — if accepted, it silently downgrades enforce→observe.
	bundle := `
apiVersion: edictum/v1
kind: ContractBundle
defaults:
  mode: enforce
contracts:
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
