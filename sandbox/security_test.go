package sandbox

import (
	"path/filepath"
	"testing"
)

// Security boundary tests for sandbox package.
// Named with TestSecurity prefix for CI filtering.

// --- 4.12: Redirect operator stripping ---

func TestSecurityRedirectOperatorStripping(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"output redirect", "echo bad >/etc/passwd"},
		{"fd redirect", "cmd 2>/tmp/err"},
		{"append redirect", "echo data >>/etc/shadow"},
		{"input redirect", "cmd </etc/shadow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t, "Bash", map[string]any{"command": tt.command})
			paths := ExtractPaths(env)
			if len(paths) == 0 {
				t.Fatal("expected at least one path extracted from redirect")
			}
			for _, p := range paths {
				if !filepath.IsAbs(p) {
					t.Errorf("expected absolute path, got %q", p)
				}
			}
		})
	}
}

func TestSecurityRedirectStrippingExposesPaths(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"output to passwd", "echo bad >/etc/passwd", "/etc/passwd"},
		{"fd2 to tmp", "cmd 2>/tmp/err", "/tmp/err"},
		{"append to shadow", "echo data >>/etc/shadow", "/etc/shadow"},
		{"input from shadow", "cmd </etc/shadow", "/etc/shadow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t, "Bash", map[string]any{"command": tt.command})
			paths := ExtractPaths(env)
			// Use resolvePath for expected value: on macOS /etc -> /private/etc
			expected := resolvePath(tt.want)
			found := false
			for _, p := range paths {
				if p == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %q in paths %v", expected, paths)
			}
		})
	}
}

func TestSecurityRedirectSentinelDenied(t *testing.T) {
	env := testEnv(t, "Bash", map[string]any{"command": "> /etc/passwd echo pwned"})
	cmd := ExtractCommand(env)
	if cmd != "\x00" {
		t.Errorf("ExtractCommand() = %q, want sentinel \\x00", cmd)
	}

	cfg := Config{
		AllowedCommands: []string{"echo", "ls", "cat"},
		Message:         "Command not allowed",
	}
	v, err := Check(env, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected deny for redirect-prefixed command, got pass")
	}
}

// --- Security: combined path + command check ---

func TestSecurityCombinedPathAndCommand(t *testing.T) {
	env := testEnv(t, "Bash", map[string]any{"command": "rm /tmp/file.txt"})
	cfg := Config{
		Within:          []string{"/tmp"},
		AllowedCommands: []string{"ls", "cat"},
		Message:         "Denied",
	}
	v, err := Check(env, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected deny when command not in allowlist, got pass")
	}
}

// --- Security: path traversal attacks ---

func TestSecurityPathTraversalAttacks(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"etc_shadow via tmp", "/tmp/../etc/shadow"},
		{"ssh key via workspace", "/root/.nanobot/workspace/../../.ssh/id_rsa"},
		{"proc environ via tmp", "/tmp/../proc/1/environ"},
		{"double traversal", "/tmp/./../../etc/passwd"},
		{"config breakout", "/root/.nanobot/workspace/../config.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t, "Read", map[string]any{"file_path": tt.path})
			cfg := Config{
				Within:  []string{"/root/.nanobot/workspace", "/tmp"},
				Message: "Denied",
			}
			v, err := Check(env, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v.Passed() {
				t.Errorf("expected deny for traversal path %q, got pass", tt.path)
			}
		})
	}
}

// --- Security: domain check ordering (blocked before allowed) ---

func TestSecurityBlockedDomainCheckedBeforeAllowed(t *testing.T) {
	env := testEnv(t, "WebFetch", map[string]any{"url": "https://evil.com/exfil"})
	cfg := Config{
		AllowedDomains: []string{"*"},
		BlockedDomains: []string{"evil.com"},
		Message:        "Denied",
	}
	v, err := Check(env, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected deny: blocked_domains should override wildcard allowed_domains")
	}
}

// --- Security: partial path name must not match ---

func TestSecurityPartialPathNameNoMatch(t *testing.T) {
	// /workspaces should NOT match /workspace prefix
	env := testEnv(t, "Read", map[string]any{"file_path": "/workspaces/file"})
	cfg := Config{
		Within:  []string{"/workspace"},
		Message: "Denied",
	}
	v, err := Check(env, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected deny: /workspaces should not match /workspace prefix")
	}
}
