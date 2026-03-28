package yaml

import (
	"context"
	"path/filepath"
	"testing"
)

// --- Security bypass tests (TestSecurity prefix for CI filtering) ---

// TestSecurityYAMLSandboxPathTraversal verifies that path traversal
// attempts through YAML-compiled sandbox rules are denied.
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
// patterns through YAML-compiled sandbox rules are denied.
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
		"ls && cat /etc/shadow",
		"ls || rm -rf /",
		"ls $(rm -rf /)",
		"ls `rm -rf /`",
		"cat /etc/shadow",
	}
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

func TestSecurityYAMLSandboxRedirectDeniedByPathConstraint(t *testing.T) {
	dir := t.TempDir()
	raw := map[string]any{
		"id":     "redirect-sandbox",
		"tool":   "Bash",
		"within": []any{dir},
		"allows": map[string]any{
			"commands": []any{"echo"},
		},
	}
	pre, err := compileSandbox(raw, "enforce")
	if err != nil {
		t.Fatalf("compileSandbox: %v", err)
	}

	env := makeSandboxEnv(t, "Bash", map[string]any{"command": "echo payload > /etc/cron.d/evil"})
	v, err := pre.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Fatal("expected deny for redirect target outside allowed paths")
	}
}

// TestSecurityYAMLSandboxDomainBypass verifies that domain bypass
// attempts through YAML-compiled sandbox rules are denied.
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
