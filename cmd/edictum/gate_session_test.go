package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/edictum-ai/edictum-go/session"
)

func TestResolveSessionIDExplicitOverride(t *testing.T) {
	id, source, err := resolveSessionID("explicit-session", "m1-read-then-edit")
	if err != nil {
		t.Fatalf("resolveSessionID: %v", err)
	}
	if id != "explicit-session" {
		t.Fatalf("id = %q, want %q", id, "explicit-session")
	}
	if source != "flag" {
		t.Fatalf("source = %q, want %q", source, "flag")
	}
}

func TestResolveSessionIDRejectsInvalidExplicitOverride(t *testing.T) {
	if _, _, err := resolveSessionID("../bad", "m1-read-then-edit"); err == nil {
		t.Fatal("expected invalid explicit session ID error, got nil")
	}
}

func TestResolveSessionIDSessionFilePrecedence(t *testing.T) {
	repo := initGitRepo(t, "feat/p3")
	sessionFile := filepath.Join(repo, gateSessionFileName)
	if err := os.WriteFile(sessionFile, []byte(`{"session_id":"from-file"}`), 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}

	withWorkingDir(t, repo, func() {
		id, source, err := resolveSessionID("", "m1-read-then-edit")
		if err != nil {
			t.Fatalf("resolveSessionID: %v", err)
		}
		if id != "from-file" {
			t.Fatalf("id = %q, want %q", id, "from-file")
		}
		if source != "file" {
			t.Fatalf("source = %q, want %q", source, "file")
		}
	})
}

func TestResolveSessionIDRejectsInvalidSessionFile(t *testing.T) {
	repo := initGitRepo(t, "feat/p3")
	sessionFile := filepath.Join(repo, gateSessionFileName)
	if err := os.WriteFile(sessionFile, []byte(`{"session_id":"../bad"}`), 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}

	withWorkingDir(t, repo, func() {
		if _, _, err := resolveSessionID("", "m1-read-then-edit"); err == nil {
			t.Fatal("expected invalid session file error, got nil")
		}
	})
}

func TestFindSessionFileWalksUpToWorktreeRoot(t *testing.T) {
	repo := initGitRepo(t, "feat/p3")
	sessionFile := filepath.Join(repo, gateSessionFileName)
	if err := os.WriteFile(sessionFile, []byte(`{"session_id":"from-root"}`), 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}

	nested := filepath.Join(repo, "internal", "workflow", "cmd")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested dir: %v", err)
	}

	withWorkingDir(t, nested, func() {
		path, err := findSessionFile()
		if err != nil {
			t.Fatalf("findSessionFile: %v", err)
		}
		gotPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatalf("EvalSymlinks(path): %v", err)
		}
		wantPath, err := filepath.EvalSymlinks(sessionFile)
		if err != nil {
			t.Fatalf("EvalSymlinks(sessionFile): %v", err)
		}
		if gotPath != wantPath {
			t.Fatalf("path = %q, want %q", gotPath, wantPath)
		}
	})
}

func TestResolveSessionIDSanitizesBranchNames(t *testing.T) {
	repo := initGitRepo(t, "feat/p3")

	withWorkingDir(t, repo, func() {
		id, source, err := resolveSessionID("", "m1-read-then-edit")
		if err != nil {
			t.Fatalf("resolveSessionID: %v", err)
		}
		if source != "git-branch" {
			t.Fatalf("source = %q, want %q", source, "git-branch")
		}
		if !strings.HasSuffix(id, "branch:feat-p3") {
			t.Fatalf("id = %q, want sanitized branch suffix", id)
		}
		if strings.Contains(id, "/") {
			t.Fatalf("id = %q, must not contain path separators", id)
		}
		if _, err := session.New(id, session.NewMemoryBackend()); err != nil {
			t.Fatalf("derived session ID must be valid: %v", err)
		}
	})
}

func TestResolveSessionIDWorktreeIsolation(t *testing.T) {
	repoOne := initGitRepo(t, "feat/p3")
	repoTwo := initGitRepo(t, "feat/p3")

	var first string
	withWorkingDir(t, repoOne, func() {
		id, _, err := resolveSessionID("", "m1-read-then-edit")
		if err != nil {
			t.Fatalf("resolveSessionID repoOne: %v", err)
		}
		first = id
	})

	withWorkingDir(t, repoTwo, func() {
		id, _, err := resolveSessionID("", "m1-read-then-edit")
		if err != nil {
			t.Fatalf("resolveSessionID repoTwo: %v", err)
		}
		if id == first {
			t.Fatalf("session IDs should differ for different worktree roots: %q", id)
		}
	})
}

func TestResolveSessionIDDetachedHeadFallsBackToWorkflowName(t *testing.T) {
	repo := initGitRepo(t, "feat/p3")
	runGit(t, repo, "checkout", "--detach", "HEAD")

	withWorkingDir(t, repo, func() {
		id, source, err := resolveSessionID("", "m1-read-then-edit")
		if err != nil {
			t.Fatalf("resolveSessionID: %v", err)
		}
		if source != "git-workflow" {
			t.Fatalf("source = %q, want %q", source, "git-workflow")
		}
		if !strings.HasSuffix(id, "wf:m1-read-then-edit") {
			t.Fatalf("id = %q, want workflow fallback suffix", id)
		}
	})
}

func TestResolveSessionIDErrorsWhenUnresolvable(t *testing.T) {
	dir := t.TempDir()
	withWorkingDir(t, dir, func() {
		if _, _, err := resolveSessionID("", ""); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func withWorkingDir(t *testing.T, dir string, fn func()) {
	t.Helper()

	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir(%q): %v", dir, err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	fn()
}

func initGitRepo(t *testing.T, branch string) string {
	t.Helper()

	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	runGit(t, repo, "checkout", "-b", "main")

	readme := filepath.Join(repo, "README.md")
	if err := os.WriteFile(readme, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "test commit")

	if branch != "" && branch != "main" {
		runGit(t, repo, "checkout", "-b", branch)
	}

	return repo
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestSanitizeDirect(t *testing.T) {
	if got := sanitize("Feat/P3"); got != "feat-p3" {
		t.Fatalf("sanitize = %q, want %q", got, "feat-p3")
	}
	if got := sanitize("hello world"); got != "hello-world" {
		t.Fatalf("sanitize = %q, want %q", got, "hello-world")
	}
}

func TestSanitizeKeepsUTF8ValidAtByteLimit(t *testing.T) {
	input := strings.Repeat("界", 43)
	got := sanitize(input)
	if !utf8.ValidString(got) {
		t.Fatalf("sanitize produced invalid UTF-8: %q", got)
	}
	if len(got) > 128 {
		t.Fatalf("sanitize length = %d, want <= 128", len(got))
	}
}
