package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const jsonValidBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle
  description: Valid test bundle.
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env", ".secret"]
    then:
      action: block
      message: "Sensitive file '{args.path}' denied."
  - id: bash-safety
    type: pre
    tool: bash
    when:
      "args.command":
        matches: "\\brm\\s+-rf\\b"
    then:
      action: block
      message: "Destructive command denied."
  - id: pii-check
    type: post
    tool: "*"
    when:
      "output.text":
        matches: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    then:
      action: warn
      message: "PII detected."
  - id: session-cap
    type: session
    limits:
      max_tool_calls: 50
    then:
      action: block
      message: "Session limit reached."
`

const jsonBundleV2 = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle-v2
  description: Updated bundle.
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env", ".secret", ".pem"]
    then:
      action: block
      message: "Sensitive file '{args.path}' denied."
  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      "principal.ticket_ref":
        exists: false
    then:
      action: block
      message: "Ticket required."
  - id: pii-check
    type: post
    tool: "*"
    when:
      "output.text":
        matches: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    then:
      action: warn
      message: "PII detected."
  - id: session-cap
    type: session
    limits:
      max_tool_calls: 100
    then:
      action: block
      message: "Session limit reached."
`

const jsonObserveBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: candidate-bundle
  description: Observe alongside candidate.
defaults:
  mode: enforce
observe_alongside: true
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env", ".secret", ".pem"]
    then:
      action: block
      message: "Candidate sensitive file rule."
`

const jsonInvalidBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bad-action
defaults:
  mode: enforce
rules:
  - id: bad-rule
    type: pre
    tool: bash
    when:
      "args.command":
        contains: "rm"
    then:
      action: warn
      message: "Wrong action for pre."
`

func writeJSONTestFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	return path
}

func mustJSONMap(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal json %q: %v", buf.String(), err)
	}
	return out
}

func TestCheckJSON_Allowed(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    `{"path":"safe.txt"}`,
		environment: "production",
		jsonOutput:  true,
	})
	if err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["tool"] != "read_file" {
		t.Fatalf("tool: got %#v", parsed["tool"])
	}
	if parsed["decision"] != "allow" {
		t.Fatalf("decision: got %#v, want allow", parsed["decision"])
	}
	if parsed["environment"] != "production" {
		t.Fatalf("environment: got %#v", parsed["environment"])
	}
	args, ok := parsed["args"].(map[string]any)
	if !ok || args["path"] != "safe.txt" {
		t.Fatalf("args: got %#v", parsed["args"])
	}
}

func TestCheckJSON_Blocked(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    `{"path":"/app/.env"}`,
		environment: "production",
		jsonOutput:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("expected exit 1, got %v", err)
	}
	parsed := mustJSONMap(t, &stdout)
	if parsed["decision"] != "block" {
		t.Fatalf("decision: got %#v, want block", parsed["decision"])
	}
	if parsed["rule_id"] != "block-env-reads" {
		t.Fatalf("rule_id: got %#v", parsed["rule_id"])
	}
	if parsed["reason"] == nil || parsed["reason"] == "" {
		t.Fatalf("reason should be present: %#v", parsed["reason"])
	}
}

func TestCheckJSON_CustomEnvironment(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    `{"path":"safe.txt"}`,
		environment: "staging",
		jsonOutput:  true,
	})
	if err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["environment"] != "staging" {
		t.Fatalf("environment: got %#v, want staging", parsed["environment"])
	}
}

func TestCheckJSON_InvalidArgs(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "read_file",
		argsJSON:    "not-json",
		environment: "production",
		jsonOutput:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "exit 2") {
		t.Fatalf("expected exit 2, got %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if _, ok := parsed["error"]; !ok {
		t.Fatalf("expected error payload, got %#v", parsed)
	}
}

func TestCheckJSON_Parseable(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	_ = runCheck(cmd, []string{path}, checkArgs{
		toolName:    "bash",
		argsJSON:    `{"command":"rm -rf /"}`,
		environment: "production",
		jsonOutput:  true,
	})

	if strings.Contains(stdout.String(), "[red") || strings.Contains(stdout.String(), "[green") || strings.Contains(stdout.String(), "[bold") {
		t.Fatalf("unexpected rich markup in %q", stdout.String())
	}
	_ = mustJSONMap(t, &stdout)
}

func TestCheckJSON_RequiredKeys(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
	cmd := newCheckCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runCheck(cmd, []string{path}, checkArgs{
		toolName:    "send_email",
		argsJSON:    `{"to":"x@y.com"}`,
		environment: "production",
		jsonOutput:  true,
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	for _, key := range []string{"tool", "args", "decision", "rules_evaluated", "environment"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("missing key %q in %#v", key, parsed)
		}
	}
}

func TestValidateJSON_ValidBundle(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
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
	files, ok := parsed["files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("files: got %#v", parsed["files"])
	}
	file := files[0].(map[string]any)
	if file["valid"] != true {
		t.Fatalf("file valid: got %#v", file["valid"])
	}
	if file["total"] != float64(4) {
		t.Fatalf("total: got %#v", file["total"])
	}
	counts := file["counts"].(map[string]any)
	if counts["pre"] != float64(2) || counts["post"] != float64(1) || counts["session"] != float64(1) {
		t.Fatalf("counts: got %#v", counts)
	}
}

func TestValidateJSON_InvalidBundle(t *testing.T) {
	path := writeJSONTestFile(t, jsonInvalidBundle)
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
	files := parsed["files"].([]any)
	file := files[0].(map[string]any)
	if file["valid"] != false {
		t.Fatalf("file valid: got %#v", file["valid"])
	}
	if _, ok := file["error"]; !ok {
		t.Fatalf("missing error in %#v", file)
	}
}

func TestValidateJSON_MixedValidInvalid(t *testing.T) {
	valid := writeJSONTestFile(t, jsonValidBundle)
	invalid := writeJSONTestFile(t, jsonInvalidBundle)
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := runValidate(cmd, []string{valid, invalid}, true)
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("expected exit 1, got %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["valid"] != false {
		t.Fatalf("valid: got %#v", parsed["valid"])
	}
	files := parsed["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("files len: got %d", len(files))
	}
	validCount := 0
	invalidCount := 0
	for _, raw := range files {
		file := raw.(map[string]any)
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
	path1 := writeJSONTestFile(t, jsonValidBundle)
	path2 := writeJSONTestFile(t, jsonObserveBundle)
	cmd := newValidateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := runValidate(cmd, []string{path1, path2}, true); err != nil {
		t.Fatalf("runValidate: %v", err)
	}

	parsed := mustJSONMap(t, &stdout)
	composed, ok := parsed["composed"].(map[string]any)
	if !ok {
		t.Fatalf("composed: got %#v", parsed["composed"])
	}
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
	files := parsed["files"].([]any)
	file := files[0].(map[string]any)
	if file["valid"] != false {
		t.Fatalf("file valid: got %#v", file["valid"])
	}
	if !strings.Contains(file["error"].(string), "not exist") && !strings.Contains(file["error"].(string), "no such file") {
		t.Fatalf("unexpected error: %q", file["error"])
	}
}

func TestValidateJSON_NoRichMarkup(t *testing.T) {
	path := writeJSONTestFile(t, jsonValidBundle)
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

func TestDiffJSON_IdenticalBundles(t *testing.T) {
	path1 := writeJSONTestFile(t, jsonValidBundle)
	path2 := writeJSONTestFile(t, jsonValidBundle)
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
	if len(parsed["added"].([]any)) != 0 || len(parsed["removed"].([]any)) != 0 || len(parsed["changed"].([]any)) != 0 {
		t.Fatalf("unexpected diff payload: %#v", parsed)
	}
	if len(parsed["unchanged"].([]any)) != 4 {
		t.Fatalf("unchanged: got %#v", parsed["unchanged"])
	}
}

func TestDiffJSON_ChangesDetected(t *testing.T) {
	oldPath := writeJSONTestFile(t, jsonValidBundle)
	newPath := writeJSONTestFile(t, jsonBundleV2)
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
	added := parsed["added"].([]any)
	removed := parsed["removed"].([]any)
	changed := parsed["changed"].([]any)
	if added[0].(map[string]any)["id"] != "require-ticket" {
		t.Fatalf("added: %#v", added)
	}
	if removed[0].(map[string]any)["id"] != "bash-safety" {
		t.Fatalf("removed: %#v", removed)
	}
	foundChanged := false
	for _, raw := range changed {
		if raw.(string) == "block-env-reads" {
			foundChanged = true
		}
	}
	if !foundChanged {
		t.Fatalf("changed: %#v", changed)
	}
}

func TestDiffJSON_AddedRulesHaveType(t *testing.T) {
	oldPath := writeJSONTestFile(t, jsonValidBundle)
	newPath := writeJSONTestFile(t, jsonBundleV2)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	_ = runDiffTwo(cmd, oldPath, newPath, true)
	parsed := mustJSONMap(t, &stdout)
	for _, raw := range parsed["added"].([]any) {
		entry := raw.(map[string]any)
		if entry["id"] == nil || entry["type"] == nil || entry["type"] == "" {
			t.Fatalf("added entry missing id/type: %#v", entry)
		}
	}
}

func TestDiffJSON_RemovedRulesHaveType(t *testing.T) {
	oldPath := writeJSONTestFile(t, jsonValidBundle)
	newPath := writeJSONTestFile(t, jsonBundleV2)
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	_ = runDiffTwo(cmd, oldPath, newPath, true)
	parsed := mustJSONMap(t, &stdout)
	for _, raw := range parsed["removed"].([]any) {
		entry := raw.(map[string]any)
		if entry["id"] == nil || entry["type"] == nil || entry["type"] == "" {
			t.Fatalf("removed entry missing id/type: %#v", entry)
		}
	}
}

func TestDiffJSON_NoRichMarkup(t *testing.T) {
	oldPath := writeJSONTestFile(t, jsonValidBundle)
	newPath := writeJSONTestFile(t, jsonBundleV2)
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
	path := writeJSONTestFile(t, jsonValidBundle)
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
	base := writeJSONTestFile(t, jsonValidBundle)
	override := writeJSONTestFile(t, jsonBundleV2)
	observe := writeJSONTestFile(t, jsonObserveBundle)
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
