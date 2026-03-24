package yaml

import (
	"context"
	"path/filepath"
	"testing"
)

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
// bypass. This is NOT a security test -- it records current behavior.
//
// The sandbox command allowlist only checks the first token. Shell operators
// that chain additional commands after the first token bypass the check
// because the first token (e.g. "ls") is in the allowlist. If any of these
// start failing, that is a security improvement -- update the expected
// behavior accordingly.
//
// Full list of metacharacters from the security checklist:
//
//	Space-separated operators: ||, &&, |
//	Embedded operators: ;, \n, \r
//	Subshell/expansion: $(), backtick, ${}, <()
//	Redirection: <<, >, >>
//
// OS-level enforcement (seccomp, AppArmor) is required for full protection.
// See also: sandbox/check.go ExtractCommand, internal/shlex.
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

	// Each entry documents a known bypass pattern where the first token "ls"
	// passes the allowlist despite dangerous operators following it.
	// Grouped by operator category for clarity.
	bypasses := []struct {
		name string
		cmd  string
	}{
		// Space-separated chaining operators
		{"or-chain (||)", "ls || rm -rf /"},
		{"and-chain (&&)", "ls && cat /etc/shadow"},
		{"pipe (|)", "ls | tee /etc/cron.d/evil"},

		// Semicolon -- command separator
		// Note: "ls; rm" has first token "ls;" which may or may not match
		// depending on shlex tokenization. We test both forms.
		{"semicolon-spaced (;)", "ls ; rm -rf /"},

		// Newline and carriage return -- command separators in shell
		{"newline (\\n)", "ls\nrm -rf /"},
		{"carriage-return (\\r)", "ls\rrm -rf /"},

		// Backtick -- command substitution
		{"backtick", "ls `rm -rf /`"},

		// $() -- command substitution (POSIX)
		{"dollar-paren $()", "ls $(rm -rf /)"},

		// ${} -- parameter expansion (can execute via ${!var} indirection)
		{"dollar-brace ${}", "ls ${IFS}rm -rf /"},

		// <() -- process substitution
		{"process-sub <()", "ls <(cat /etc/shadow)"},

		// << -- here-document (can inject multi-line input)
		{"here-doc (<<)", "ls <<EOF\nrm -rf /\nEOF"},

		// > -- output redirection (can overwrite files)
		{"redirect-out (>)", "ls > /etc/cron.d/evil"},

		// >> -- append redirection (can append to files)
		{"redirect-append (>>)", "ls >> /etc/cron.d/evil"},
	}
	for _, tc := range bypasses {
		t.Run(tc.name, func(t *testing.T) {
			env := makeSandboxEnv(t, "Bash", map[string]any{"command": tc.cmd})
			v, err := pre.Check(context.Background(), env)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.cmd, err)
			}
			if !v.Passed() {
				// If this fires, the sandbox now catches this pattern --
				// that is a security improvement. Update docs and move
				// this case to TestSecurityYAMLSandboxCommandInjection.
				t.Logf("bypass %q is now caught -- security improvement", tc.name)
			}
		})
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
