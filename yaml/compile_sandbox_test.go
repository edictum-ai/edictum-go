package yaml

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/edictum-ai/edictum-go/envelope"
)

func makeSandboxEnv(t *testing.T, tool string, args map[string]any) envelope.ToolEnvelope {
	t.Helper()
	env, err := envelope.CreateEnvelope(context.Background(), envelope.CreateEnvelopeOptions{
		ToolName: tool,
		Args:     args,
	})
	if err != nil {
		t.Fatalf("CreateEnvelope: %v", err)
	}
	return env
}

// TestCompileSandbox_WithinAllows verifies that a sandbox contract with
// "within" paths produces a Check that allows paths inside the boundary.
func TestCompileSandbox_WithinAllows(t *testing.T) {
	// Use a temp dir so the path exists and resolves consistently.
	dir := t.TempDir()
	raw := map[string]any{
		"id":   "safe-paths",
		"tool": "read_file",
		"within": []any{
			dir,
		},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	if pre.Name != "safe-paths" {
		t.Errorf("Name: got %q, want %q", pre.Name, "safe-paths")
	}
	if pre.Source != "yaml_sandbox" {
		t.Errorf("Source: got %q, want %q", pre.Source, "yaml_sandbox")
	}

	// Resolve the dir the same way ExtractPaths would.
	resolved, _ := filepath.EvalSymlinks(dir)
	env := makeSandboxEnv(t, "read_file", map[string]any{"path": resolved + "/notes.txt"})
	v, err := pre.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed() {
		t.Errorf("expected pass for path within %s, got fail: %s", dir, v.Message())
	}
}

// TestCompileSandbox_WithinDenies verifies that a path outside the boundary
// is denied.
func TestCompileSandbox_WithinDenies(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]any{
		"id":      "safe-paths",
		"tool":    "read_file",
		"within":  []any{dir},
		"message": "restricted path",
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	env := makeSandboxEnv(t, "read_file", map[string]any{"path": "/etc/passwd"})
	v, err := pre.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected fail for path outside boundary, got pass")
	}
	if v.Message() != "restricted path" {
		t.Errorf("message: got %q, want custom message", v.Message())
	}
}

// TestCompileSandbox_NotWithinDenies verifies that not_within exclusions
// deny paths even within allowed prefixes.
func TestCompileSandbox_NotWithinDenies(t *testing.T) {
	dir := t.TempDir()
	excluded := filepath.Join(dir, "secret")
	if err := os.MkdirAll(excluded, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{
		"id":         "safe-paths",
		"tool":       "read_file",
		"within":     []any{dir},
		"not_within": []any{excluded},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	resolved, _ := filepath.EvalSymlinks(excluded)
	env := makeSandboxEnv(t, "read_file", map[string]any{"path": resolved + "/id_rsa"})
	v, err := pre.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected fail for path in not_within, got pass")
	}
}

// TestCompileSandbox_AllowedCommands verifies command allowlist.
func TestCompileSandbox_AllowedCommands(t *testing.T) {
	raw := map[string]any{
		"id":   "cmd-sandbox",
		"tool": "Bash",
		"allows": map[string]any{
			"commands": []any{"ls", "cat", "grep"},
		},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	// Allowed command
	env := makeSandboxEnv(t, "Bash", map[string]any{"command": "ls -la /tmp"})
	v, err := pre.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed() {
		t.Errorf("expected pass for 'ls', got fail: %s", v.Message())
	}

	// Denied command
	env = makeSandboxEnv(t, "Bash", map[string]any{"command": "rm -rf /tmp"})
	v, err = pre.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected fail for 'rm', got pass")
	}
}

// TestCompileSandbox_ObserveMode verifies _observe flag sets mode correctly.
func TestCompileSandbox_ObserveMode(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]any{
		"id":       "obs-sandbox",
		"tool":     "Bash",
		"_observe": true,
		"within":   []any{dir},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}
	if pre.Mode != "observe" {
		t.Errorf("Mode: got %q, want %q", pre.Mode, "observe")
	}
}

// TestCompileSandbox_DefaultTool verifies wildcard tool when not specified.
func TestCompileSandbox_DefaultTool(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]any{
		"id":     "no-tool",
		"within": []any{dir},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}
	if pre.Tool != "*" {
		t.Errorf("Tool: got %q, want %q", pre.Tool, "*")
	}
}

// TestCompileSandbox_NonExistentPathErrors verifies that non-existent
// boundary paths produce an error instead of silently degrading.
func TestCompileSandbox_NonExistentPathErrors(t *testing.T) {
	raw := map[string]any{
		"id":     "bad-paths",
		"tool":   "read_file",
		"within": []any{"/nonexistent/path/that/does/not/exist"},
	}
	_, err := compileSandbox(raw, "enforce")
	if err == nil {
		t.Fatal("expected error for non-existent boundary path, got nil")
	}
}

// TestParseSandboxConfig verifies full config extraction.
func TestParseSandboxConfig(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{
		"within":     []any{dir, subdir},
		"not_within": []any{subdir},
		"message":    "sandbox violation",
		"allows": map[string]any{
			"commands": []any{"ls", "cat"},
			"domains":  []any{"*.example.com"},
		},
		"not_allows": map[string]any{
			"domains": []any{"evil.com"},
		},
	}
	cfg, err := parseSandboxConfig(raw)
	if err != nil {
		t.Fatalf("parseSandboxConfig: %v", err)
	}

	if len(cfg.Within) != 2 {
		t.Errorf("Within length: got %d, want 2", len(cfg.Within))
	}
	if len(cfg.NotWithin) != 1 {
		t.Errorf("NotWithin length: got %d, want 1", len(cfg.NotWithin))
	}
	if cfg.Message != "sandbox violation" {
		t.Errorf("Message: got %q", cfg.Message)
	}
	if len(cfg.AllowedCommands) != 2 || cfg.AllowedCommands[0] != "ls" {
		t.Errorf("AllowedCommands: got %v", cfg.AllowedCommands)
	}
	if len(cfg.AllowedDomains) != 1 || cfg.AllowedDomains[0] != "*.example.com" {
		t.Errorf("AllowedDomains: got %v", cfg.AllowedDomains)
	}
	if len(cfg.BlockedDomains) != 1 || cfg.BlockedDomains[0] != "evil.com" {
		t.Errorf("BlockedDomains: got %v", cfg.BlockedDomains)
	}
}

// TestToStringSlice covers edge cases.
func TestToStringSlice(t *testing.T) {
	if got := toStringSlice(nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := toStringSlice("not a slice"); got != nil {
		t.Errorf("string input: got %v, want nil", got)
	}
	if got := toStringSlice([]any{42, true}); got != nil {
		t.Errorf("non-string items: got %v, want nil", got)
	}
	got := toStringSlice([]any{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("valid input: got %v, want [a b]", got)
	}
}

// --- Security bypass tests (TestSecurity prefix for CI filtering) ---

// TestSecurityYAMLSandboxPathTraversal verifies that path traversal
// attempts through YAML-compiled sandbox contracts are denied.
func TestSecurityYAMLSandboxPathTraversal(t *testing.T) {
	dir := t.TempDir()
	resolved, _ := filepath.EvalSymlinks(dir)
	raw := map[string]any{
		"id":     "safe-paths",
		"tool":   "read_file",
		"within": []any{dir},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	traversals := []string{
		resolved + "/../etc/shadow",
		resolved + "/./../../etc/passwd",
		resolved + "/../../../root/.bashrc",
	}
	for _, p := range traversals {
		env := makeSandboxEnv(t, "read_file", map[string]any{"path": p})
		v, err := pre.Check(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", p, err)
		}
		if v.Passed() {
			t.Errorf("expected deny for traversal %q via YAML-compiled sandbox", p)
		}
	}
}

// TestSecurityYAMLSandboxCommandInjection verifies that command injection
// patterns through YAML-compiled sandbox contracts are denied.
func TestSecurityYAMLSandboxCommandInjection(t *testing.T) {
	raw := map[string]any{
		"id":   "cmd-sandbox",
		"tool": "Bash",
		"allows": map[string]any{
			"commands": []any{"ls"},
		},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	injections := []string{
		"rm -rf /",
		"ls; rm -rf /",
		"cat /etc/shadow",
	}
	// NOTE: shell chaining patterns like "ls || rm -rf /" are a known
	// limitation of first-token-only command classification in sandbox.Check.
	// The first token "ls" is in the allowlist, so these pass. OS-level
	// enforcement (seccomp, AppArmor) is required for full protection.
	// See also: sandbox/check.go ExtractCommand, internal/shlex.
	for _, cmd := range injections {
		env := makeSandboxEnv(t, "Bash", map[string]any{"command": cmd})
		v, err := pre.Check(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", cmd, err)
		}
		if v.Passed() {
			t.Errorf("expected deny for command %q via YAML-compiled sandbox", cmd)
		}
	}
}

// TestKnownLimitation_CommandChaining documents the known first-token-only
// bypass. This is NOT a security test — it records current behavior.
// Space-separated chaining operators (||, &&, |) pass through the command
// allowlist because only the first token is checked. If this test starts
// failing, that is a security improvement.
func TestKnownLimitation_CommandChaining(t *testing.T) {
	raw := map[string]any{
		"id":   "cmd-sandbox",
		"tool": "Bash",
		"allows": map[string]any{
			"commands": []any{"ls"},
		},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	// These bypass the sandbox because first token "ls" is in the allowlist.
	// Fixing this requires OS-level enforcement or multi-token command analysis.
	bypasses := []string{
		"ls || rm -rf /",
		"ls && cat /etc/shadow",
		"ls | tee /etc/cron.d/evil",
	}
	for _, cmd := range bypasses {
		env := makeSandboxEnv(t, "Bash", map[string]any{"command": cmd})
		v, err := pre.Check(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", cmd, err)
		}
		if !v.Passed() {
			// If this fires, the sandbox now catches chaining — update docs.
			t.Logf("bypass %q is now caught — security improvement", cmd)
		}
	}
}

// TestSecurityYAMLSandboxDomainBypass verifies that domain bypass
// attempts through YAML-compiled sandbox contracts are denied.
func TestSecurityYAMLSandboxDomainBypass(t *testing.T) {
	raw := map[string]any{
		"id":   "domain-sandbox",
		"tool": "fetch",
		"allows": map[string]any{
			"domains": []any{"*.example.com"},
		},
		"not_allows": map[string]any{
			"domains": []any{"evil.example.com"},
		},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	bypasses := []struct {
		url  string
		deny bool
	}{
		{"https://evil.example.com/data", true},
		{"https://attacker.com/payload", true},
		{"https://safe.example.com/api", false},
	}
	for _, tc := range bypasses {
		env := makeSandboxEnv(t, "fetch", map[string]any{"url": tc.url})
		v, err := pre.Check(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", tc.url, err)
		}
		if tc.deny && v.Passed() {
			t.Errorf("expected deny for %q via YAML-compiled sandbox", tc.url)
		}
		if !tc.deny && !v.Passed() {
			t.Errorf("expected pass for %q via YAML-compiled sandbox, got: %s", tc.url, v.Message())
		}
	}
}
