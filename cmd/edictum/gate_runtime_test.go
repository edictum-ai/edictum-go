package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const gateReadThenEditWorkflow = `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: m1-read-then-edit
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: "Read the spec first"
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
`

const gateApprovalWorkflow = `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: m1-approval-flow
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: "Review required before bash"
  - id: verify
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
`

const gateThreeStageWorkflow = `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: m1-three-stage
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: "Read the spec first"
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
  - id: verify
    entry:
      - condition: stage_complete("implement")
    tools: [Bash]
`

func TestGateRunWithoutWorkflowAllowsExistingPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	input := `{"tool_name":"Read","tool_input":{"path":"README.md"}}`

	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input,
		[]string{
			"--format", "raw",
			"--rules", rulesPath,
			"--session-id", "gate-run-no-workflow",
			runner,
		},
	)
	if err != nil {
		t.Fatalf("gate run error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if stdout != "runner ok" {
		t.Fatalf("stdout = %q, want %q", stdout, "runner ok")
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestGateRunWorkflowBlocksRealPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateReadThenEditWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	input := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`

	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input,
		[]string{
			"--format", "raw",
			"--rules", rulesPath,
			"--workflow", workflowPath,
			"--session-id", "gate-run-blocked",
			runner,
		},
	)
	if err == nil || err.Error() != "exit 1" {
		t.Fatalf("err = %v, want exit 1\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "Read the spec first") {
		t.Fatalf("stderr = %q, want workflow block", stderr)
	}
}

func TestGateRunWorkflowProgressesAcrossInvocations(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateReadThenEditWorkflow)
	sessionID := "gate-run-progress"
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	readInput := `{"tool_name":"Read","tool_input":{"path":"spec.md"}}`
	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), readInput,
		[]string{
			"--format", "raw",
			"--rules", rulesPath,
			"--workflow", workflowPath,
			"--session-id", sessionID,
			runner,
		},
	)
	if err != nil {
		t.Fatalf("read step error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	editInput := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`
	stdout, stderr, err = runGateCommand(t, newGateRunCmd(), editInput,
		[]string{
			"--format", "raw",
			"--rules", rulesPath,
			"--workflow", workflowPath,
			"--session-id", sessionID,
			runner,
		},
	)
	if err != nil {
		t.Fatalf("edit step error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if stdout != "runner ok" {
		t.Fatalf("stdout = %q, want %q", stdout, "runner ok")
	}
}

func TestGateRunInvalidWorkflowFailsClearly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", "apiVersion: edictum/v1\nkind: Workflow\nmetadata:\n  name: bad\nstages:\n  - id: read\n    tools: [Read]\n    nope: true\n")
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	input := `{"tool_name":"Read","tool_input":{"path":"spec.md"}}`

	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input,
		[]string{
			"--format", "raw",
			"--rules", rulesPath,
			"--workflow", workflowPath,
			"--session-id", "gate-run-invalid-workflow",
			runner,
		},
	)
	if err == nil {
		t.Fatalf("expected error, got nil\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "loading workflow") {
		t.Fatalf("err = %v, want loading workflow", err)
	}
}

func TestGateRunWorkflowApprovalFlow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	server := newApprovalTestServer()
	defer server.Close()

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateApprovalWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	writeGateConfigForTest(t, &gateConfig{
		ServerURL:    server.URL,
		APIKey:       "test-key",
		RulesPath:    rulesPath,
		WorkflowPath: workflowPath,
		AuditPath:    filepath.Join(t.TempDir(), "audit"),
	})

	sessionID := "gate-run-approval"

	editInput := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`
	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), editInput,
		[]string{
			"--format", "raw",
			"--session-id", sessionID,
			runner,
		},
	)
	if err != nil {
		t.Fatalf("implement step error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	bashInput := `{"tool_name":"Bash","tool_input":{"command":"git status"}}`
	stdout, stderr, err = runGateCommand(t, newGateRunCmd(), bashInput,
		[]string{
			"--format", "raw",
			"--session-id", sessionID,
			runner,
		},
	)
	if err != nil {
		t.Fatalf("approval step error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if stdout != "runner ok" {
		t.Fatalf("stdout = %q, want %q", stdout, "runner ok")
	}
}

func TestGateRunAutoResolvesSessionIDFromBranch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	repo := initGitRepo(t, "feat/p3")
	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateReadThenEditWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	input := `{"tool_name":"Read","tool_input":{"path":"spec.md"}}`

	withWorkingDir(t, repo, func() {
		stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input,
			[]string{
				"--format", "raw",
				"--rules", rulesPath,
				"--workflow", workflowPath,
				runner,
			},
		)
		if err != nil {
			t.Fatalf("gate run error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
		}
		if stdout != "runner ok" {
			t.Fatalf("stdout = %q, want %q", stdout, "runner ok")
		}
		if !strings.Contains(stderr, "Using session: repo:") || !strings.Contains(stderr, "git-branch") {
			t.Fatalf("stderr = %q, want auto-resolved session message", stderr)
		}
	})
}

func TestGateInitRulesDirectorySucceeds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "base.yaml"), []byte(validBundleYAML), 0o600); err != nil {
		t.Fatalf("write rules dir file: %v", err)
	}

	cmd := newGateInitCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--rules", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	cfg, err := loadGateConfigDefault()
	if err != nil {
		t.Fatalf("loadGateConfigDefault: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.RulesPath, "base.yaml")); err != nil {
		t.Fatalf("copied rules file missing: %v", err)
	}
}

func TestGateInitRulesFileStillWorks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)

	cmd := newGateInitCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--rules", rulesPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	cfg, err := loadGateConfigDefault()
	if err != nil {
		t.Fatalf("loadGateConfigDefault: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.RulesPath, filepath.Base(rulesPath))); err != nil {
		t.Fatalf("copied rules file missing: %v", err)
	}
}

func TestGateRunAppendsWALEventOnAllow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	input := `{"tool_name":"Read","tool_input":{"path":"README.md"}}`
	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input, []string{
		"--format", "raw",
		"--session-id", "gate-run-audit",
		runner,
	})
	if err != nil {
		t.Fatalf("gate run error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	cfg, err := loadGateConfigDefault()
	if err != nil {
		t.Fatalf("loadGateConfigDefault: %v", err)
	}
	events, err := readWALEvents(cfg.AuditPath, 10, "Read", "allow")
	if err != nil {
		t.Fatalf("readWALEvents: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected gate run to append a WAL audit event")
	}
}

func TestGateRunAppendsWALEventOnBlock(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateReadThenEditWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath, "--workflow", workflowPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	input := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`
	_, _, err := runGateCommand(t, newGateRunCmd(), input, []string{
		"--format", "raw",
		"--session-id", "gate-run-audit-block",
		runner,
	})
	if err == nil || err.Error() != "exit 1" {
		t.Fatalf("err = %v, want exit 1", err)
	}

	cfg, err := loadGateConfigDefault()
	if err != nil {
		t.Fatalf("loadGateConfigDefault: %v", err)
	}
	events, err := readWALEvents(cfg.AuditPath, 10, "Edit", "block")
	if err != nil {
		t.Fatalf("readWALEvents: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected blocked gate run to append a WAL audit event")
	}
}

func TestGateAuditShowsGateRunActivity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	input := `{"tool_name":"Read","tool_input":{"path":"README.md"}}`
	if _, _, err := runGateCommand(t, newGateRunCmd(), input, []string{
		"--format", "raw",
		"--session-id", "gate-run-audit-visible",
		runner,
	}); err != nil {
		t.Fatalf("gate run error: %v", err)
	}

	auditCmd := newGateAuditCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	auditCmd.SetOut(&stdout)
	auditCmd.SetErr(&stderr)
	auditCmd.SetArgs([]string{"--json", "--limit", "10"})
	if err := auditCmd.Execute(); err != nil {
		t.Fatalf("gate audit error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	parsed := mustJSONMap(t, &stdout)
	events := mustSlice(t, parsed["events"], "events")
	if len(events) == 0 {
		t.Fatal("expected gate audit output to include gate run activity")
	}
}

func TestGateStatusPendingCountReflectsGateRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	input := `{"tool_name":"Read","tool_input":{"path":"README.md"}}`
	if _, _, err := runGateCommand(t, newGateRunCmd(), input, []string{
		"--format", "raw",
		"--session-id", "gate-run-status",
		runner,
	}); err != nil {
		t.Fatalf("gate run error: %v", err)
	}

	statusCmd := newGateStatusCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	statusCmd.SetOut(&stdout)
	statusCmd.SetErr(&stderr)
	statusCmd.SetArgs([]string{"--json"})
	if err := statusCmd.Execute(); err != nil {
		t.Fatalf("gate status error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	parsed := mustJSONMap(t, &stdout)
	if parsed["pending_events"] != float64(1) {
		t.Fatalf("pending_events = %#v, want 1", parsed["pending_events"])
	}
}

func TestGateSyncPostsEventsToCanonicalEndpoint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	if _, _, err := runGateCommand(t, newGateRunCmd(), `{"tool_name":"Read","tool_input":{"path":"README.md"}}`, []string{
		"--format", "raw",
		"--session-id", "gate-sync-canonical-endpoint",
		runner,
	}); err != nil {
		t.Fatalf("gate run error: %v", err)
	}

	type syncRequest struct {
		Path          string
		Authorization string
		Body          map[string]any
		Err           string
	}

	reqCh := make(chan syncRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			reqCh <- syncRequest{Err: fmt.Sprintf("decode sync body: %v", err)}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reqCh <- syncRequest{
			Path:          r.URL.Path,
			Authorization: r.Header.Get("Authorization"),
			Body:          body,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg, err := loadGateConfigDefault()
	if err != nil {
		t.Fatalf("loadGateConfigDefault: %v", err)
	}
	cfg.ServerURL = server.URL
	cfg.APIKey = "test-key"
	writeGateConfigForTest(t, cfg)

	syncCmd := newGateSyncCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	syncCmd.SetOut(&stdout)
	syncCmd.SetErr(&stderr)
	syncCmd.SetArgs([]string{"--json"})
	if err := syncCmd.Execute(); err != nil {
		t.Fatalf("gate sync error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	req := <-reqCh
	if req.Err != "" {
		t.Fatal(req.Err)
	}
	if req.Path != "/v1/events" {
		t.Fatalf("sync path = %q, want %q", req.Path, "/v1/events")
	}
	if req.Authorization != "Bearer test-key" {
		t.Fatalf("authorization = %q, want %q", req.Authorization, "Bearer test-key")
	}
	events, ok := req.Body["events"].([]any)
	if !ok {
		t.Fatalf("sync body missing events array: %#v", req.Body)
	}
	if len(events) != 1 {
		t.Fatalf("events length = %d, want 1", len(events))
	}
}

func TestGateStatusConfiguredWorkflowShowsUnresolvedSession(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateThreeStageWorkflow)

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath, "--workflow", workflowPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	nonRepoDir := t.TempDir()
	withWorkingDir(t, nonRepoDir, func() {
		statusCmd := newGateStatusCmd()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		statusCmd.SetOut(&stdout)
		statusCmd.SetErr(&stderr)
		statusCmd.SetArgs(nil)
		if err := statusCmd.Execute(); err != nil {
			t.Fatalf("gate status error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}

		output := stdout.String()
		if !strings.Contains(output, "Workflow:  m1-three-stage") {
			t.Fatalf("stdout = %q, want workflow name", output)
		}
		if !strings.Contains(output, "Workflow State:") {
			t.Fatalf("stdout = %q, want workflow state section", output)
		}
		if !strings.Contains(output, "Session: unresolved") {
			t.Fatalf("stdout = %q, want unresolved session", output)
		}
		if !strings.Contains(output, "Reason: cannot resolve session ID") {
			t.Fatalf("stdout = %q, want resolution failure reason", output)
		}
		if !strings.Contains(output, gateWorkflowResolutionHint) {
			t.Fatalf("stdout = %q, want resolution hint", output)
		}
	})
}

func TestGateStatusExplicitSessionShowsWorkflowState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateThreeStageWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	sessionID := "manual-session"

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath, "--workflow", workflowPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	readInput := `{"tool_name":"Read","tool_input":{"path":"spec.md"}}`
	editInput := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`
	if _, _, err := runGateCommand(t, newGateRunCmd(), readInput, []string{
		"--format", "raw",
		"--session-id", sessionID,
		runner,
	}); err != nil {
		t.Fatalf("read step error: %v", err)
	}
	if _, _, err := runGateCommand(t, newGateRunCmd(), editInput, []string{
		"--format", "raw",
		"--session-id", sessionID,
		runner,
	}); err != nil {
		t.Fatalf("edit step error: %v", err)
	}

	nonRepoDir := t.TempDir()
	withWorkingDir(t, nonRepoDir, func() {
		statusCmd := newGateStatusCmd()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		statusCmd.SetOut(&stdout)
		statusCmd.SetErr(&stderr)
		statusCmd.SetArgs([]string{"--json", "--session-id", sessionID})
		if err := statusCmd.Execute(); err != nil {
			t.Fatalf("gate status error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}

		parsed := mustJSONMap(t, &stdout)
		if parsed["workflow_session_resolved"] != true {
			t.Fatalf("workflow_session_resolved = %#v, want true", parsed["workflow_session_resolved"])
		}
		if parsed["workflow_state_exists"] != true {
			t.Fatalf("workflow_state_exists = %#v, want true", parsed["workflow_state_exists"])
		}
		if parsed["workflow_session_id"] != sessionID {
			t.Fatalf("workflow_session_id = %#v, want %q", parsed["workflow_session_id"], sessionID)
		}
		if parsed["workflow_session_source"] != "flag" {
			t.Fatalf("workflow_session_source = %#v, want %q", parsed["workflow_session_source"], "flag")
		}
		if parsed["workflow_current_stage"] != "implement" {
			t.Fatalf("workflow_current_stage = %#v, want %q", parsed["workflow_current_stage"], "implement")
		}
	})
}

func TestGateStatusExplicitSessionWithoutStateShowsClearly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateThreeStageWorkflow)
	sessionID := "empty-session"

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath, "--workflow", workflowPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	nonRepoDir := t.TempDir()
	withWorkingDir(t, nonRepoDir, func() {
		statusCmd := newGateStatusCmd()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		statusCmd.SetOut(&stdout)
		statusCmd.SetErr(&stderr)
		statusCmd.SetArgs([]string{"--json", "--session-id", sessionID})
		if err := statusCmd.Execute(); err != nil {
			t.Fatalf("gate status error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}

		parsed := mustJSONMap(t, &stdout)
		if parsed["workflow_session_resolved"] != true {
			t.Fatalf("workflow_session_resolved = %#v, want true", parsed["workflow_session_resolved"])
		}
		if parsed["workflow_state_exists"] != false {
			t.Fatalf("workflow_state_exists = %#v, want false", parsed["workflow_state_exists"])
		}
		if parsed["workflow_state"] != "not_started" {
			t.Fatalf("workflow_state = %#v, want %q", parsed["workflow_state"], "not_started")
		}
	})
}

func TestGateStatusShowsWorkflowSessionProgress(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	repo := initGitRepo(t, "feat/p3")
	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateThreeStageWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath, "--workflow", workflowPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	readInput := `{"tool_name":"Read","tool_input":{"path":"spec.md"}}`
	editInput := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`
	withWorkingDir(t, repo, func() {
		if _, _, err := runGateCommand(t, newGateRunCmd(), readInput, []string{
			"--format", "raw",
			runner,
		}); err != nil {
			t.Fatalf("gate run error: %v", err)
		}
		if _, _, err := runGateCommand(t, newGateRunCmd(), editInput, []string{
			"--format", "raw",
			runner,
		}); err != nil {
			t.Fatalf("gate run error: %v", err)
		}

		statusCmd := newGateStatusCmd()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		statusCmd.SetOut(&stdout)
		statusCmd.SetErr(&stderr)
		statusCmd.SetArgs([]string{"--json"})
		if err := statusCmd.Execute(); err != nil {
			t.Fatalf("gate status error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}

		parsed := mustJSONMap(t, &stdout)
		if parsed["workflow"] != "m1-three-stage" {
			t.Fatalf("workflow = %#v, want %q", parsed["workflow"], "m1-three-stage")
		}
		if got := parsed["workflow_session_id"]; got == nil || !strings.Contains(got.(string), "branch:feat-p3") {
			t.Fatalf("workflow_session_id = %#v, want branch-derived session", got)
		}
		if parsed["workflow_current_stage"] != "implement" {
			t.Fatalf("workflow_current_stage = %#v, want %q", parsed["workflow_current_stage"], "implement")
		}
		progress := mustJSONMapFromAny(t, parsed["workflow_progress"], "workflow_progress")
		if progress["current"] != float64(2) || progress["total"] != float64(3) {
			t.Fatalf("workflow_progress = %#v, want 2/3", progress)
		}
		completed := mustSlice(t, parsed["workflow_completed_stages"], "workflow_completed_stages")
		if len(completed) != 1 || completed[0] != "read-context" {
			t.Fatalf("workflow_completed_stages = %#v, want [read-context]", completed)
		}
		if parsed["workflow_next_stage"] != "verify" {
			t.Fatalf("workflow_next_stage = %#v, want %q", parsed["workflow_next_stage"], "verify")
		}
	})
}

func TestGateResetUsesResolvedSessionID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	repo := initGitRepo(t, "feat/p3")
	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateThreeStageWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath, "--workflow", workflowPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	readInput := `{"tool_name":"Read","tool_input":{"path":"spec.md"}}`
	editInput := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`

	withWorkingDir(t, repo, func() {
		if _, _, err := runGateCommand(t, newGateRunCmd(), readInput, []string{
			"--format", "raw",
			runner,
		}); err != nil {
			t.Fatalf("read step error: %v", err)
		}
		if _, _, err := runGateCommand(t, newGateRunCmd(), editInput, []string{
			"--format", "raw",
			runner,
		}); err != nil {
			t.Fatalf("edit step error: %v", err)
		}

		resetCmd := newGateResetCmd()
		var resetOut bytes.Buffer
		var resetErr bytes.Buffer
		resetCmd.SetOut(&resetOut)
		resetCmd.SetErr(&resetErr)
		resetCmd.SetArgs([]string{"--stage", "implement"})
		if err := resetCmd.Execute(); err != nil {
			t.Fatalf("gate reset error: %v\nstdout:\n%s\nstderr:\n%s", err, resetOut.String(), resetErr.String())
		}
		if !strings.Contains(resetOut.String(), "Session: repo:") || !strings.Contains(resetOut.String(), "git-branch") {
			t.Fatalf("reset output = %q, want resolved session details", resetOut.String())
		}

		statusCmd := newGateStatusCmd()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		statusCmd.SetOut(&stdout)
		statusCmd.SetErr(&stderr)
		statusCmd.SetArgs([]string{"--json"})
		if err := statusCmd.Execute(); err != nil {
			t.Fatalf("gate status error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}

		parsed := mustJSONMap(t, &stdout)
		if parsed["workflow_current_stage"] != "implement" {
			t.Fatalf("workflow_current_stage = %#v, want %q", parsed["workflow_current_stage"], "implement")
		}
		completed := mustSlice(t, parsed["workflow_completed_stages"], "workflow_completed_stages")
		if len(completed) != 1 || completed[0] != "read-context" {
			t.Fatalf("workflow_completed_stages = %#v, want [read-context]", completed)
		}
		if parsed["workflow_next_stage"] != "verify" {
			t.Fatalf("workflow_next_stage = %#v, want %q", parsed["workflow_next_stage"], "verify")
		}
	})
}

func TestGateResetExplicitSessionResetsWorkflowState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateThreeStageWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	sessionID := "explicit-reset-session"

	initCmd := newGateInitCmd()
	initCmd.SetOut(io.Discard)
	initCmd.SetErr(io.Discard)
	initCmd.SetArgs([]string{"--rules", rulesPath, "--workflow", workflowPath})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("gate init error: %v", err)
	}

	readInput := `{"tool_name":"Read","tool_input":{"path":"spec.md"}}`
	editInput := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`
	if _, _, err := runGateCommand(t, newGateRunCmd(), readInput, []string{
		"--format", "raw",
		"--session-id", sessionID,
		runner,
	}); err != nil {
		t.Fatalf("read step error: %v", err)
	}
	if _, _, err := runGateCommand(t, newGateRunCmd(), editInput, []string{
		"--format", "raw",
		"--session-id", sessionID,
		runner,
	}); err != nil {
		t.Fatalf("edit step error: %v", err)
	}

	nonRepoDir := t.TempDir()
	withWorkingDir(t, nonRepoDir, func() {
		resetCmd := newGateResetCmd()
		var resetOut bytes.Buffer
		var resetErr bytes.Buffer
		resetCmd.SetOut(&resetOut)
		resetCmd.SetErr(&resetErr)
		resetCmd.SetArgs([]string{"--stage", "implement", "--session-id", sessionID})
		if err := resetCmd.Execute(); err != nil {
			t.Fatalf("gate reset error: %v\nstdout:\n%s\nstderr:\n%s", err, resetOut.String(), resetErr.String())
		}
		if !strings.Contains(resetOut.String(), "Session: "+sessionID) {
			t.Fatalf("reset output = %q, want explicit session", resetOut.String())
		}

		statusCmd := newGateStatusCmd()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		statusCmd.SetOut(&stdout)
		statusCmd.SetErr(&stderr)
		statusCmd.SetArgs([]string{"--json", "--session-id", sessionID})
		if err := statusCmd.Execute(); err != nil {
			t.Fatalf("gate status error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}

		parsed := mustJSONMap(t, &stdout)
		if parsed["workflow_current_stage"] != "implement" {
			t.Fatalf("workflow_current_stage = %#v, want %q", parsed["workflow_current_stage"], "implement")
		}
		completed := mustSlice(t, parsed["workflow_completed_stages"], "workflow_completed_stages")
		if len(completed) != 1 || completed[0] != "read-context" {
			t.Fatalf("workflow_completed_stages = %#v, want [read-context]", completed)
		}
	})
}

func runGateCommand(t *testing.T, cmd *cobra.Command, input string, args []string) (string, string, error) {
	t.Helper()

	cmd.SetIn(strings.NewReader(input))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func writeGateRunnerScript(t *testing.T, body string) string {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("gate runner script helper is unix-only")
	}

	path := filepath.Join(t.TempDir(), "runner.sh")
	content := "#!/bin/sh\nset -eu\n" + body
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("writeGateRunnerScript: %v", err)
	}
	return path
}

func writeGateConfigForTest(t *testing.T, cfg *gateConfig) {
	t.Helper()

	gateDir, err := gateDirectory()
	if err != nil {
		t.Fatalf("gateDirectory: %v", err)
	}
	if err := os.MkdirAll(gateDir, 0o755); err != nil {
		t.Fatalf("mkdir gate dir: %v", err)
	}
	if err := writeGateConfig(filepath.Join(gateDir, "config.json"), cfg); err != nil {
		t.Fatalf("writeGateConfig: %v", err)
	}
}

func mustJSONMapFromAny(t *testing.T, raw any, name string) map[string]any {
	t.Helper()

	parsed, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", name, raw)
	}
	return parsed
}

func newApprovalTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
			_, _ = fmt.Fprint(w, `{"id":"approval-1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/approval-1":
			_, _ = fmt.Fprint(w, `{"status":"approved","decided_by":"reviewer","decision_reason":"approved"}`)
		default:
			http.NotFound(w, r)
		}
	}))
}
