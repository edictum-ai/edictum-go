package main

import (
	"strings"
	"testing"
)

func TestHelp(t *testing.T) {
	code, out := runEdictum(t, "--help")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Usage:") || !strings.Contains(out, "Available Commands:") {
		t.Fatalf("expected root help output, got:\n%s", out)
	}
}

func TestValidateHelp(t *testing.T) {
	code, out := runEdictum(t, "validate", "--help")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "edictum validate <files...>") {
		t.Fatalf("expected validate help output, got:\n%s", out)
	}
}

func TestCheckHelp(t *testing.T) {
	code, out := runEdictum(t, "check", "--help")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "edictum check <files...>") || !strings.Contains(out, "--tool") {
		t.Fatalf("expected check help output, got:\n%s", out)
	}
}

func TestCheckMissingArgs(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", validBundleYAML)

	code, out := runEdictum(t, "check", bundle)
	if code == 0 {
		t.Fatalf("exit code = %d, want non-zero\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "required flag") {
		t.Fatalf("expected missing args error, got:\n%s", out)
	}
}

func TestNoCommand(t *testing.T) {
	code, out := runEdictum(t)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Available Commands:") {
		t.Fatalf("expected root usage output, got:\n%s", out)
	}
}

func TestVersion(t *testing.T) {
	code, out := runEdictum(t, "version")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "edictum ") || !strings.Contains(out, "go ") {
		t.Fatalf("expected version output, got:\n%s", out)
	}
}
