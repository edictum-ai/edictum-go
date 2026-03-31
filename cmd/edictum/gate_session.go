package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/edictum-ai/edictum-go/session"
)

const gateSessionFileName = ".edictum-session"

var (
	sessionGetwd    = os.Getwd
	sessionReadFile = os.ReadFile
	sessionGitExec  = gitOutput
)

type gateSessionFile struct {
	SessionID string `json:"session_id"`
}

func resolveSessionID(explicit, workflowName string) (id string, source string, err error) {
	if explicit != "" {
		if err := validateResolvedSessionID(explicit); err != nil {
			return "", "", fmt.Errorf("--session-id is invalid: %w", err)
		}
		return explicit, "flag", nil
	}

	if path, err := findSessionFile(); err == nil {
		if resolved, ok := readSessionFile(path); ok {
			if err := validateResolvedSessionID(resolved); err != nil {
				return "", "", fmt.Errorf("%s contains invalid session_id: %w", gateSessionFileName, err)
			}
			return resolved, "file", nil
		}
	}

	toplevel, err := worktreeIdentity()
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve session ID: not in a git repo, no .edictum-session file, and no --session-id flag provided")
	}

	hash := sessionHash(toplevel)
	if branch, err := currentBranch(); err == nil {
		resolved := fmt.Sprintf("repo:%s:branch:%s", hash, sanitize(branch))
		if err := validateResolvedSessionID(resolved); err != nil {
			return "", "", err
		}
		return resolved, "git-branch", nil
	}

	if workflowName != "" {
		resolved := fmt.Sprintf("repo:%s:wf:%s", hash, sanitize(workflowName))
		if err := validateResolvedSessionID(resolved); err != nil {
			return "", "", err
		}
		return resolved, "git-workflow", nil
	}

	return "", "", fmt.Errorf("cannot resolve session ID: not in a git repo, no .edictum-session file, and no --session-id flag provided")
}

func findSessionFile() (string, error) {
	dir, err := sessionGetwd()
	if err != nil {
		return "", err
	}

	stopDir := ""
	if root, err := worktreeIdentity(); err == nil {
		stopDir = filepath.Clean(root)
	}

	dir = filepath.Clean(dir)
	for {
		candidate := filepath.Join(dir, gateSessionFileName)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}

		if stopDir != "" && dir == stopDir {
			break
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("no %s found", gateSessionFileName)
}

func worktreeIdentity() (string, error) {
	out, err := sessionGitExec("rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("not in a git repository")
	}
	return filepath.Clean(out), nil
}

func currentBranch() (string, error) {
	return sessionGitExec("symbolic-ref", "--short", "HEAD")
}

func sanitize(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var b strings.Builder
	for _, r := range value {
		runeBytes := utf8.RuneLen(r)
		if runeBytes < 0 {
			continue
		}
		if b.Len()+runeBytes > 128 {
			break
		}
		switch {
		case r == '/' || r == '\\':
			b.WriteByte('-')
		case unicode.IsSpace(r):
			b.WriteByte('-')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func readSessionFile(path string) (string, bool) {
	data, err := sessionReadFile(path)
	if err != nil {
		return "", false
	}
	var file gateSessionFile
	if err := json.Unmarshal(data, &file); err != nil {
		return "", false
	}
	if file.SessionID == "" {
		return "", false
	}
	return file.SessionID, true
}

func validateResolvedSessionID(id string) error {
	if _, err := session.New(id, session.NewMemoryBackend()); err != nil {
		return fmt.Errorf("resolved session ID %q is invalid: %w", id, err)
	}
	return nil
}

func sessionHash(toplevel string) string {
	sum := sha256.Sum256([]byte(toplevel))
	return hex.EncodeToString(sum[:])[:12]
}

func gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", msg)
	}
	return strings.TrimSpace(string(out)), nil
}
