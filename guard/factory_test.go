package guard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
)

const validBundle = `apiVersion: edictum/v2
kind: Ruleset
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
      action: redact`

const toolsMergeBundle = `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: t1
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "test"
    then:
      action: block
      message: "test"
tools:
  Bash:
    side_effect: irreversible
  ReadFile:
    side_effect: read
    idempotent: true`

// --- FromYAMLString tests ---

func TestFromYAMLString_LoadsContracts(t *testing.T) {
	g, err := FromYAMLString(validBundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(g.state.preconditions) != 1 {
		t.Errorf("preconditions: got %d, want 1", len(g.state.preconditions))
	}
	if len(g.state.postconditions) != 1 {
		t.Errorf("postconditions: got %d, want 1", len(g.state.postconditions))
	}
	if g.state.preconditions[0].Name != "no-rm" {
		t.Errorf("precondition name: got %q, want %q", g.state.preconditions[0].Name, "no-rm")
	}
	if g.state.postconditions[0].Name != "redact-keys" {
		t.Errorf("postcondition name: got %q, want %q", g.state.postconditions[0].Name, "redact-keys")
	}
}

func TestFromYAMLString_DefaultMode(t *testing.T) {
	g, err := FromYAMLString(validBundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The YAML defaults.mode is "enforce"; guard should inherit it.
	if g.Mode() != "enforce" {
		t.Errorf("mode: got %q, want %q", g.Mode(), "enforce")
	}
}

func TestFromYAMLString_ModeOverride(t *testing.T) {
	// YAML sets defaults.mode: enforce, but WithMode overrides to observe.
	g, err := FromYAMLString(validBundle, WithMode("observe"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if g.Mode() != "observe" {
		t.Errorf("mode: got %q, want %q (user override should win)", g.Mode(), "observe")
	}
}

func TestFromYAMLString_PolicyVersion(t *testing.T) {
	g, err := FromYAMLString(validBundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "f16fafc8c7d2815cd9cc49e6f4156b2dff51f77e03f33fb7a1cf3ee2006fc126"
	if g.PolicyVersion() != want {
		t.Errorf("policy_version:\n  got  %q\n  want %q", g.PolicyVersion(), want)
	}
}

func TestFromYAMLString_EnvironmentPassthrough(t *testing.T) {
	g, err := FromYAMLString(validBundle, WithEnvironment("staging"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if g.environment != "staging" {
		t.Errorf("environment: got %q, want %q", g.environment, "staging")
	}
}

func TestFromYAMLString_InvalidYAML(t *testing.T) {
	_, err := FromYAMLString("not: [valid: yaml: {{{}}")
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

func TestFromYAMLString_ToolsMerge(t *testing.T) {
	// YAML defines Bash=irreversible and ReadFile=read.
	// User option sets Bash=write. User should win on conflict.
	g, err := FromYAMLString(toolsMergeBundle, WithTools(map[string]map[string]any{
		"Bash": {"side_effect": "write"},
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Bash: user option ("write") overrides YAML ("irreversible").
	bashSE, _ := g.toolRegistry.Classify("Bash")
	if string(bashSE) != "write" {
		t.Errorf("Bash side_effect: got %q, want %q (user should win)", bashSE, "write")
	}

	// ReadFile: only in YAML, should be preserved.
	readSE, readIdem := g.toolRegistry.Classify("ReadFile")
	if string(readSE) != "read" {
		t.Errorf("ReadFile side_effect: got %q, want %q", readSE, "read")
	}
	if !readIdem {
		t.Error("ReadFile idempotent: got false, want true")
	}
}

// --- FromYAML (file/directory) tests ---

func TestFromYAML_Directory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "01-base.yaml"), validBundle)
	writeFile(t, filepath.Join(dir, "02-extra.yaml"), `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: extra-pre
    type: pre
    tool: ReadFile
    when:
      "args.path":
        contains: "/etc"
    then:
      action: block
      message: "no /etc reads"`)

	g, err := FromYAML(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1 pre from base (no-rm) + 1 pre from extra (extra-pre) = 2
	if len(g.state.preconditions) != 2 {
		t.Errorf("preconditions: got %d, want 2", len(g.state.preconditions))
	}
	// 1 post from base (redact-keys)
	if len(g.state.postconditions) != 1 {
		t.Errorf("postconditions: got %d, want 1", len(g.state.postconditions))
	}
}

func TestFromYAML_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	writeFile(t, path, validBundle)

	g, err := FromYAML(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(g.state.preconditions) != 1 {
		t.Errorf("preconditions: got %d, want 1", len(g.state.preconditions))
	}
	if len(g.state.postconditions) != 1 {
		t.Errorf("postconditions: got %d, want 1", len(g.state.postconditions))
	}
}

func TestFromYAML_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	_, err := FromYAML(dir)
	if err == nil {
		t.Fatal("expected error for empty directory, got nil")
	}
}

func TestFromYAML_NonexistentPath(t *testing.T) {
	_, err := FromYAML("/nonexistent/path/to/bundle.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
}

// --- FromYAMLWithReport tests ---

func TestFromYAMLWithReport_MultiFile(t *testing.T) {
	dir := t.TempDir()

	// File 1: defines rule "shared-id"
	writeFile(t, filepath.Join(dir, "01-base.yaml"), `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: shared-id
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "echo"
    then:
      action: block
      message: "base version"`)

	// File 2: overrides "shared-id" with a different message
	writeFile(t, filepath.Join(dir, "02-override.yaml"), `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: shared-id
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "echo override"
    then:
      action: block
      message: "override version"`)

	g, report, err := FromYAMLWithReport(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Guard should have exactly 1 precondition (override replaces base).
	if len(g.state.preconditions) != 1 {
		t.Errorf("preconditions: got %d, want 1", len(g.state.preconditions))
	}

	// Report should record the override.
	if report == nil {
		t.Fatal("report should not be nil")
	}
	if len(report.Overrides) != 1 {
		t.Fatalf("overrides: got %d, want 1", len(report.Overrides))
	}

	ov := report.Overrides[0]
	if ov.RuleID != "shared-id" {
		t.Errorf("override contract_id: got %q, want %q", ov.RuleID, "shared-id")
	}
	// Canonicalize expected paths — t.TempDir() may not be canonical
	// (e.g. /var → /private/var on macOS).
	canonDir, _ := filepath.EvalSymlinks(dir)
	basePath := filepath.Join(canonDir, "01-base.yaml")
	overridePath := filepath.Join(canonDir, "02-override.yaml")
	if ov.OriginalSource != basePath {
		t.Errorf("original_source: got %q, want %q", ov.OriginalSource, basePath)
	}
	if ov.OverriddenBy != overridePath {
		t.Errorf("overridden_by: got %q, want %q", ov.OverriddenBy, overridePath)
	}
}

// --- ReloadFromYAML tests ---

func TestReloadFromYAML_SwapsContracts(t *testing.T) {
	// Start with validBundle (1 pre + 1 post).
	g, err := FromYAMLString(validBundle)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}

	if len(g.state.preconditions) != 1 {
		t.Fatalf("initial preconditions: got %d, want 1", len(g.state.preconditions))
	}
	if len(g.state.postconditions) != 1 {
		t.Fatalf("initial postconditions: got %d, want 1", len(g.state.postconditions))
	}
	oldVersion := g.PolicyVersion()

	// Reload with a different bundle that has 2 preconditions and 0 postconditions.
	newYAML := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: rule-a
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "ls"
    then:
      action: block
      message: "no ls"
  - id: rule-b
    type: pre
    tool: ReadFile
    when:
      "args.path":
        contains: "/tmp"
    then:
      action: block
      message: "no tmp reads"`

	if err := g.ReloadFromYAML([]byte(newYAML)); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if len(g.state.preconditions) != 2 {
		t.Errorf("reloaded preconditions: got %d, want 2", len(g.state.preconditions))
	}
	if len(g.state.postconditions) != 0 {
		t.Errorf("reloaded postconditions: got %d, want 0", len(g.state.postconditions))
	}
	if g.PolicyVersion() == oldVersion {
		t.Error("policy version should change after reload")
	}
}

// --- Security bypass tests ---

func TestSecurityResolvePaths_SymlinkEscape(t *testing.T) {
	// Place a valid file inside the dir so FromYAML doesn't error on empty dir.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "01-legit.yaml"), validBundle)

	// Create an escaping symlink to a file outside the directory.
	externalDir := t.TempDir()
	writeFile(t, filepath.Join(externalDir, "evil.yaml"), `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: injected
    type: session`)
	link := filepath.Join(dir, "02-escape.yaml")
	if err := os.Symlink(filepath.Join(externalDir, "evil.yaml"), link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	g, err := FromYAML(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the legit file's rules (1 pre + 1 post) should load.
	// The escaping symlink's session rule must be skipped.
	if len(g.state.sessionRules) != 0 {
		t.Error("escaping symlink was not skipped — session rule loaded from outside")
	}
}

func TestSecurityResolvePaths_SymlinkToParent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "secret.yaml"), `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: parent-secret
    type: session`)

	dir := filepath.Join(root, "rules")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "01-legit.yaml"), validBundle)

	link := filepath.Join(dir, "02-traversal.yaml")
	if err := os.Symlink(filepath.Join(root, "secret.yaml"), link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	g, err := FromYAML(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.state.sessionRules) != 0 {
		t.Error("parent-directory symlink was not skipped — session rule loaded")
	}
}

func TestReloadFromYAML_ToolRegistryReplaced(t *testing.T) {
	yamlWithTools := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: t1
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "ls"
    then:
      action: block
      message: "no ls"
tools:
  OldTool:
    side_effect: read
    idempotent: true`
	g, err := FromYAMLString(yamlWithTools)
	if err != nil {
		t.Fatal(err)
	}
	se, idem := g.toolRegistry.Classify("OldTool")
	if se != "read" || !idem {
		t.Fatalf("OldTool before: got (%q, %v), want (read, true)", se, idem)
	}

	// Reload with bundle that has no tools section — OldTool should be gone.
	newYAML := `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: t2
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "rm"
    then:
      action: block
      message: "no rm"`
	if err := g.ReloadFromYAML([]byte(newYAML)); err != nil {
		t.Fatal(err)
	}
	// After reload, OldTool returns the default (irreversible, false).
	se2, idem2 := g.toolRegistry.Classify("OldTool")
	if se2 == "read" || idem2 {
		t.Error("OldTool should have been cleared after reload without tools section")
	}
}

// --- YAML sandbox integration tests (issue #35) ---

func sandboxWithinYAML(dir string) string {
	return fmt.Sprintf(`apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: safe-file-paths
    type: sandbox
    tool: read_file
    within: ["%s"]
    message: "read_file restricted"`, dir)
}

func TestFromYAMLString_SandboxWithinAllows(t *testing.T) {
	dir := t.TempDir()
	resolved, _ := filepath.EvalSymlinks(dir)
	g, err := FromYAMLString(sandboxWithinYAML(dir))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.state.sandboxRules) != 1 {
		t.Fatalf("sandbox rules: got %d, want 1", len(g.state.sandboxRules))
	}

	ctx := context.Background()
	result, err := g.Run(ctx, "read_file", map[string]any{"path": resolved + "/notes.txt"}, func(_ map[string]any) (any, error) {
		return "file contents", nil
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if result != "file contents" {
		t.Errorf("expected tool result, got %v", result)
	}
}

func TestFromYAMLString_SandboxWithinDenies(t *testing.T) {
	dir := t.TempDir()
	g, err := FromYAMLString(sandboxWithinYAML(dir))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	_, err = g.Run(ctx, "read_file", map[string]any{"path": "/etc/passwd"}, func(_ map[string]any) (any, error) {
		t.Fatal("callable should not be invoked on deny")
		return nil, nil
	})
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError for path outside boundary, got %T: %v", err, err)
	}
}

func TestFromYAMLString_SandboxNotWithinDenies(t *testing.T) {
	dir := t.TempDir()
	excluded := filepath.Join(dir, "secret")
	if err := os.MkdirAll(excluded, 0o700); err != nil {
		t.Fatal(err)
	}
	resolvedDir, _ := filepath.EvalSymlinks(dir)
	resolvedExcluded, _ := filepath.EvalSymlinks(excluded)

	yamlStr := fmt.Sprintf(`apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: safe-but-no-secret
    type: sandbox
    tool: read_file
    within: ["%s"]
    not_within: ["%s"]
    message: "secret dir is off limits"`, dir, excluded)

	g, err := FromYAMLString(yamlStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	// Path within dir but excluded by not_within
	_, err = g.Run(ctx, "read_file", map[string]any{"path": resolvedExcluded + "/id_rsa"}, func(_ map[string]any) (any, error) {
		t.Fatal("callable should not be invoked on deny")
		return nil, nil
	})
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError for path in not_within, got %T: %v", err, err)
	}

	// Path within dir and not excluded
	result, err := g.Run(ctx, "read_file", map[string]any{"path": resolvedDir + "/readme.txt"}, func(_ map[string]any) (any, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %v", result)
	}
}

const sandboxCommandsBundle = `apiVersion: edictum/v2
kind: Ruleset
rules:
  - id: safe-commands
    type: sandbox
    tool: Bash
    allows:
      commands: ["ls", "cat", "grep"]
    message: "Only ls, cat, grep allowed"`

func TestFromYAMLString_SandboxCommandAllowDeny(t *testing.T) {
	g, err := FromYAMLString(sandboxCommandsBundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()

	// Allowed command
	result, err := g.Run(ctx, "Bash", map[string]any{"command": "ls -la /tmp"}, func(_ map[string]any) (any, error) {
		return "output", nil
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if result != "output" {
		t.Errorf("expected 'output', got %v", result)
	}

	// Denied command
	_, err = g.Run(ctx, "Bash", map[string]any{"command": "rm -rf /tmp"}, func(_ map[string]any) (any, error) {
		t.Fatal("callable should not be invoked on deny")
		return nil, nil
	})
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError for 'rm', got %T: %v", err, err)
	}
}

func TestReloadFromYAML_SandboxRulesWired(t *testing.T) {
	dir := t.TempDir()

	// Start with no sandbox rules.
	g, err := FromYAMLString(validBundle)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if len(g.state.sandboxRules) != 0 {
		t.Fatalf("initial sandbox: got %d, want 0", len(g.state.sandboxRules))
	}

	// Reload with sandbox rules — they must be wired with real Check logic.
	if err := g.ReloadFromYAML([]byte(sandboxWithinYAML(dir))); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(g.state.sandboxRules) != 1 {
		t.Fatalf("reloaded sandbox: got %d, want 1", len(g.state.sandboxRules))
	}

	ctx := context.Background()
	_, err = g.Run(ctx, "read_file", map[string]any{"path": "/etc/shadow"}, func(_ map[string]any) (any, error) {
		t.Fatal("callable should not be invoked on deny")
		return nil, nil
	})
	var denied *edictum.BlockedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected BlockedError after reload, got %T: %v", err, err)
	}
}

// writeFile is a test helper that creates a file with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFile(%q): %v", path, err)
	}
}
