package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateJSON_ValidBundle(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runValidate(cmd, []string{path}, true); err != nil {
		t.Fatalf("runValidate: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["valid"] != true {
		t.Fatalf("valid: got %#v", parsed["valid"])
	}
	files := mustSlice(t, parsed["files"], "files")
	if len(files) != 1 {
		t.Fatalf("files: got %#v", parsed["files"])
	}
	file := mustMap(t, files[0], "files[0]")
	if file["valid"] != true || file["total"] != float64(4) {
		t.Fatalf("unexpected file payload: %#v", file)
	}
	counts := mustMap(t, file["counts"], "counts")
	if counts["pre"] != float64(2) || counts["post"] != float64(1) || counts["session"] != float64(1) {
		t.Fatalf("counts: got %#v", counts)
	}
}

func TestValidateJSON_InvalidBundle(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonInvalidBundle)
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runValidate(cmd, []string{path}, true)
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("expected exit 1, got %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["valid"] != false {
		t.Fatalf("valid: got %#v", parsed["valid"])
	}
	files := mustSlice(t, parsed["files"], "files")
	file := mustMap(t, files[0], "files[0]")
	if file["valid"] != false {
		t.Fatalf("file valid: got %#v", file["valid"])
	}
	if _, ok := file["error"]; !ok {
		t.Fatalf("missing error in %#v", file)
	}
}

func TestValidateJSON_MixedValidInvalid(t *testing.T) {
	valid := writeTempFile(t, "valid.yaml", jsonValidBundle)
	invalid := writeTempFile(t, "invalid.yaml", jsonInvalidBundle)
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runValidate(cmd, []string{valid, invalid}, true)
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("expected exit 1, got %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	files := mustSlice(t, parsed["files"], "files")
	if parsed["valid"] != false || len(files) != 2 {
		t.Fatalf("unexpected payload: %#v", parsed)
	}
	validCount := 0
	invalidCount := 0
	for _, raw := range files {
		file := mustMap(t, raw, "file")
		if file["valid"] == true {
			validCount++
		} else {
			invalidCount++
		}
	}
	if validCount != 1 || invalidCount != 1 {
		t.Fatalf("valid=%d invalid=%d", validCount, invalidCount)
	}
}

func TestValidateJSON_Composition(t *testing.T) {
	path1 := writeTempFile(t, "base.yaml", jsonValidBundle)
	path2 := writeTempFile(t, "observe.yaml", jsonObserveBundle)
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runValidate(cmd, []string{path1, path2}, true); err != nil {
		t.Fatalf("runValidate: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	composed := mustMap(t, parsed["composed"], "composed")
	if _, ok := composed["observes"]; !ok {
		t.Fatalf("expected observes in %#v", composed)
	}
}

func TestValidateJSON_NonexistentFile(t *testing.T) {
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runValidate(cmd, []string{"/nonexistent/file.yaml"}, true)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["valid"] != false {
		t.Fatalf("valid: got %#v", parsed["valid"])
	}
	files := mustSlice(t, parsed["files"], "files")
	file := mustMap(t, files[0], "files[0]")
	if file["valid"] != false {
		t.Fatalf("file valid: got %#v", file["valid"])
	}
	errMsg, ok := file["error"].(string)
	if !ok {
		t.Fatalf("expected error string, got %T", file["error"])
	}
	if !strings.Contains(errMsg, "not exist") && !strings.Contains(errMsg, "no such file") {
		t.Fatalf("unexpected error: %q", errMsg)
	}
}

func TestValidateJSON_NoRichMarkup(t *testing.T) {
	path := writeTempFile(t, "rules.yaml", jsonValidBundle)
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runValidate(cmd, []string{path}, true); err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if strings.Contains(stdout.String(), "[green") || strings.Contains(stdout.String(), "[red") {
		t.Fatalf("unexpected rich markup in %q", stdout.String())
	}
	_ = mustJSONMap(t, &stdout)
}
