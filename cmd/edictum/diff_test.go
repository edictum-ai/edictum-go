package main

import (
	"strings"
	"testing"
)

func TestDiff_IdenticalBundles(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", validBundleYAML)

	code, out := runEdictum(t, "diff", path, path)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Summary: 0 added, 0 removed, 0 changed") {
		t.Fatalf("expected zero-diff summary, got:\n%s", out)
	}
}

func TestDiff_AddedRule(t *testing.T) {
	path1 := writeTempFile(t, "base.yaml", validBundleYAML)
	path2 := writeTempFile(t, "updated.yaml", bundleV2YAML)

	code, out := runEdictum(t, "diff", path1, path2)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "+ require-ticket (type: pre)") {
		t.Fatalf("expected added rule in output, got:\n%s", out)
	}
}

func TestDiff_RemovedRule(t *testing.T) {
	path1 := writeTempFile(t, "updated.yaml", bundleV2YAML)
	path2 := writeTempFile(t, "base.yaml", validBundleYAML)

	code, out := runEdictum(t, "diff", path1, path2)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "- require-ticket (type: pre)") {
		t.Fatalf("expected removed rule in output, got:\n%s", out)
	}
}

func TestDiff_ChangedRule(t *testing.T) {
	path1 := writeTempFile(t, "base.yaml", validBundleYAML)
	path2 := writeTempFile(t, "updated.yaml", bundleV2YAML)

	code, out := runEdictum(t, "diff", path1, path2)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "~ block-env-reads") {
		t.Fatalf("expected changed rule output, got:\n%s", out)
	}
}

func TestDiff_ChangedSessionLimits(t *testing.T) {
	path1 := writeTempFile(t, "base.yaml", validBundleYAML)
	path2 := writeTempFile(t, "updated.yaml", bundleV2YAML)

	code, out := runEdictum(t, "diff", path1, path2)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "~ session-cap") {
		t.Fatalf("expected session limit change in output, got:\n%s", out)
	}
}

func TestDiff_ShowsSummary(t *testing.T) {
	path1 := writeTempFile(t, "base.yaml", validBundleYAML)
	path2 := writeTempFile(t, "updated.yaml", bundleV2YAML)

	code, out := runEdictum(t, "diff", path1, path2)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Summary:") || !strings.Contains(out, "1 added, 1 removed, 2 changed, 1 unchanged") {
		t.Fatalf("expected summary output, got:\n%s", out)
	}
}

func TestDiff_InvalidFile(t *testing.T) {
	valid := writeTempFile(t, "valid.yaml", validBundleYAML)
	invalid := writeTempFile(t, "invalid.yaml", invalidYAMLSyntax)

	code, out := runEdictum(t, "diff", valid, invalid)
	if code != 1 && code != 2 {
		t.Fatalf("exit code = %d, want 1 or 2\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "loading") && !strings.Contains(strings.ToLower(out), "yaml") {
		t.Fatalf("expected invalid YAML error, got:\n%s", out)
	}
}
