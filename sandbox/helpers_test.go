package sandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/edictum-ai/edictum-go/rule"
)

// Unit tests for helper functions and edge cases.

func TestDomainMatches(t *testing.T) {
	tests := []struct {
		hostname string
		patterns []string
		want     bool
	}{
		{"github.com", []string{"github.com"}, true},
		{"evil.com", []string{"github.com"}, false},
		{"storage.googleapis.com", []string{"*.googleapis.com"}, true},
		{"googleapis.com", []string{"*.googleapis.com"}, false},
		{"evil.com", []string{"evil.com", "webhook.site"}, true},
		{"example.com", []string{"*"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.hostname+"_"+tt.patterns[0], func(t *testing.T) {
			got := DomainMatches(tt.hostname, tt.patterns)
			if got != tt.want {
				t.Errorf("DomainMatches(%q, %v) = %v, want %v",
					tt.hostname, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestExtractCommand(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args map[string]any
		want string
	}{
		{"simple command", "Bash", map[string]any{"command": "ls -la"}, "ls"},
		{"empty command", "Bash", map[string]any{"command": ""}, ""},
		{"no command arg", "Read", map[string]any{"file_path": "/tmp/x"}, ""},
		{"git with args", "Bash", map[string]any{"command": "git clone https://github.com/repo"}, "git"},
		{"redirect prefix", "Bash", map[string]any{"command": "> /tmp/out echo hi"}, "\x00"},
		{"fd redirect prefix", "Bash", map[string]any{"command": "2>/tmp/err cmd"}, "\x00"},
		{"semicolon chaining", "Bash", map[string]any{"command": "ls; rm -rf /"}, "\x00"},
		{"background execution", "Bash", map[string]any{"command": "ls & rm -rf /"}, "\x00"},
		{"logical and chaining", "Bash", map[string]any{"command": "ls && cat /etc/shadow"}, "\x00"},
		{"command substitution", "Bash", map[string]any{"command": "ls $(rm -rf /)"}, "\x00"},
		{"write process substitution", "Bash", map[string]any{"command": "ls >(cat /etc/shadow)"}, "\x00"},
		{"herestring", "Bash", map[string]any{"command": "ls <<< $(cat /etc/shadow)"}, "\x00"},
		{"ansi c quoting", "Bash", map[string]any{"command": "echo $'\\x3b' rm -rf /"}, "\x00"},
		{"safe output redirect", "Bash", map[string]any{"command": "echo hi > /tmp/out"}, "echo"},
		{"safe input redirect", "Bash", map[string]any{"command": "cat < /tmp/in"}, "cat"},
		{"environment variable expansion allowed", "Bash", map[string]any{"command": "echo $HOME"}, "echo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t, tt.tool, tt.args)
			got := ExtractCommand(env)
			if got != tt.want {
				t.Errorf("ExtractCommand() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPathNotWithin(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		excluded []string
		want     bool
	}{
		{"exact match", "/workspace/.git", []string{"/workspace/.git"}, true},
		{"subdirectory match", "/workspace/.git/config", []string{"/workspace/.git"}, true},
		{"no match", "/workspace/src", []string{"/workspace/.git"}, false},
		{"empty excluded", "/workspace/.git", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PathNotWithin(tt.path, tt.excluded)
			if got != tt.want {
				t.Errorf("PathNotWithin(%q, %v) = %v, want %v", tt.path, tt.excluded, got, tt.want)
			}
		})
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/repo", "github.com"},
		{"http://evil.com:8080/path", "evil.com"},
		{"ftp://files.example.com", "files.example.com"},
		{"not-a-url", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractHostname(tt.url)
			if got != tt.want {
				t.Errorf("extractHostname(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

// --- Edge cases ---

func TestCheckDefaultMessage(t *testing.T) {
	env := testEnv(t, "Read", map[string]any{"file_path": "/etc/shadow"})
	cfg := Config{Within: []string{"/workspace"}}
	v, err := Check(env, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed() {
		t.Error("expected deny")
	}
	if v.Message() != defaultMessage {
		t.Errorf("message = %q, want default %q", v.Message(), defaultMessage)
	}
}

func TestCheckNoConstraintsPass(t *testing.T) {
	env := testEnv(t, "Read", map[string]any{"file_path": "/etc/shadow"})
	v, err := Check(env, Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed() {
		t.Error("expected pass when no constraints configured")
	}
}

func TestCheckReturnsContractVerdict(t *testing.T) {
	env := testEnv(t, "Read", map[string]any{"file_path": "/workspace/file.txt"})
	v, err := Check(env, Config{Within: []string{"/workspace"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reflect.TypeOf(v) != reflect.TypeOf(rule.Pass()) {
		t.Errorf("Check() returned wrong type: %T", v)
	}
}

func TestCheckNoPathsExtractedPass(t *testing.T) {
	env := testEnv(t, "WebFetch", map[string]any{"query": "weather"})
	cfg := Config{Within: []string{"/workspace"}, Message: "Denied"}
	v, err := Check(env, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed() {
		t.Error("expected pass when no paths extracted, got fail")
	}
}

func TestExtractPathsDeduplication(t *testing.T) {
	env := testEnv(t, "Read", map[string]any{
		"file_path": "/tmp/file.txt",
		"path":      "/tmp/file.txt",
	})
	paths := ExtractPaths(env)
	seen := make(map[string]bool)
	for _, p := range paths {
		if seen[p] {
			t.Errorf("duplicate path %q in extracted paths", p)
		}
		seen[p] = true
	}
}

func TestResolvePath_ResolvesSymlinkedParentForMissingLeaf(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(linkDir, "new", "file.txt")
	got := resolvePath(target)
	wantBase, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(wantBase, "new", "file.txt")
	if got != want {
		t.Fatalf("resolvePath(%q) = %q, want %q", target, got, want)
	}
}
