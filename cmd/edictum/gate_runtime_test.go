package main

import (
	"bytes"
	"fmt"
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
		ServerURL:     server.URL,
		APIKey:        "test-key",
		ContractsPath: rulesPath,
		WorkflowPath:  workflowPath,
		AuditPath:     filepath.Join(t.TempDir(), "audit"),
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

func newApprovalTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/approvals":
			_, _ = fmt.Fprint(w, `{"id":"approval-1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/approvals/approval-1":
			_, _ = fmt.Fprint(w, `{"status":"approved","decided_by":"reviewer","decision_reason":"approved"}`)
		default:
			http.NotFound(w, r)
		}
	}))
}
