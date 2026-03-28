package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDiffJSON_IdenticalBundles(t *testing.T) {
	path1 := writeTempFile(t, "old.yaml", jsonValidBundle)
	path2 := writeTempFile(t, "new.yaml", jsonValidBundle)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runDiffTwo(cmd, path1, path2, true); err != nil {
		t.Fatalf("runDiffTwo: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["has_changes"] != false {
		t.Fatalf("has_changes: got %#v", parsed["has_changes"])
	}
	if len(mustSlice(t, parsed["added"], "added")) != 0 || len(mustSlice(t, parsed["removed"], "removed")) != 0 || len(mustSlice(t, parsed["changed"], "changed")) != 0 {
		t.Fatalf("unexpected diff payload: %#v", parsed)
	}
	if len(mustSlice(t, parsed["unchanged"], "unchanged")) != 4 {
		t.Fatalf("unchanged: got %#v", parsed["unchanged"])
	}
}

func TestDiffJSON_ChangesDetected(t *testing.T) {
	oldPath := writeTempFile(t, "old.yaml", jsonValidBundle)
	newPath := writeTempFile(t, "new.yaml", jsonBundleV2)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runDiffTwo(cmd, oldPath, newPath, true); err != nil {
		t.Fatalf("runDiffTwo: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["has_changes"] != true {
		t.Fatalf("has_changes: got %#v", parsed["has_changes"])
	}
	added := mustSlice(t, parsed["added"], "added")
	removed := mustSlice(t, parsed["removed"], "removed")
	changed := mustSlice(t, parsed["changed"], "changed")
	if mustMap(t, added[0], "added[0]")["id"] != "require-ticket" {
		t.Fatalf("added: %#v", added)
	}
	if mustMap(t, removed[0], "removed[0]")["id"] != "bash-safety" {
		t.Fatalf("removed: %#v", removed)
	}
	foundChanged := false
	for _, raw := range changed {
		id, ok := raw.(string)
		if !ok {
			t.Fatalf("expected changed entry to be string, got %T", raw)
		}
		if id == "block-env-reads" {
			foundChanged = true
		}
	}
	if !foundChanged {
		t.Fatalf("changed: %#v", changed)
	}
}

func TestDiffJSON_AddedRulesHaveType(t *testing.T) {
	oldPath := writeTempFile(t, "old.yaml", jsonValidBundle)
	newPath := writeTempFile(t, "new.yaml", jsonBundleV2)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	_ = runDiffTwo(cmd, oldPath, newPath, true)
	parsed := mustJSONMap(t, &stdout)
	for _, raw := range mustSlice(t, parsed["added"], "added") {
		entry := mustMap(t, raw, "added entry")
		if entry["id"] == nil || entry["type"] == nil || entry["type"] == "" {
			t.Fatalf("added entry missing id/type: %#v", entry)
		}
	}
}

func TestDiffJSON_RemovedRulesHaveType(t *testing.T) {
	oldPath := writeTempFile(t, "old.yaml", jsonValidBundle)
	newPath := writeTempFile(t, "new.yaml", jsonBundleV2)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	_ = runDiffTwo(cmd, oldPath, newPath, true)
	parsed := mustJSONMap(t, &stdout)
	for _, raw := range mustSlice(t, parsed["removed"], "removed") {
		entry := mustMap(t, raw, "removed entry")
		if entry["id"] == nil || entry["type"] == nil || entry["type"] == "" {
			t.Fatalf("removed entry missing id/type: %#v", entry)
		}
	}
}

func TestDiffJSON_NoRichMarkup(t *testing.T) {
	oldPath := writeTempFile(t, "old.yaml", jsonValidBundle)
	newPath := writeTempFile(t, "new.yaml", jsonBundleV2)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	_ = runDiffTwo(cmd, oldPath, newPath, true)
	if strings.Contains(stdout.String(), "[green") || strings.Contains(stdout.String(), "[red") || strings.Contains(stdout.String(), "[yellow") {
		t.Fatalf("unexpected rich markup in %q", stdout.String())
	}
	_ = mustJSONMap(t, &stdout)
}

func TestDiffJSON_TooFewFiles(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{path, "--json"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for too few files")
	}
	if !strings.Contains(stdout.String(), "requires at least 2 arg") {
		t.Fatalf("expected cobra arg validation error, got %q", stdout.String())
	}
}

func TestDiffJSON_CompositionReport(t *testing.T) {
	base := writeTempFile(t, "base.yaml", jsonValidBundle)
	override := writeTempFile(t, "override.yaml", jsonBundleV2)
	observe := writeTempFile(t, "observe.yaml", jsonObserveBundle)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runDiffCompose(cmd, []string{base, override, observe}, true)
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("expected exit 1, got %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if _, ok := parsed["Overrides"]; !ok {
		t.Fatalf("expected Overrides in %#v", parsed)
	}
	if _, ok := parsed["Observes"]; !ok {
		t.Fatalf("expected Observes in %#v", parsed)
	}
}
