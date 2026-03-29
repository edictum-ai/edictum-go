package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const gateExecWorkflow = `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: m1-exec-workflow
stages:
  - id: verify
    tools: [Bash]
    exit:
      - condition: exec("printf ok", exit_code=0)
        message: "exec must be enabled explicitly"
`

func TestSecurityGateRunWorkflowExecRequiresFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateExecWorkflow)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	input := `{"tool_name":"Bash","tool_input":{"command":"git status"}}`

	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input, []string{
		"--format", "raw",
		"--rules", rulesPath,
		"--workflow", workflowPath,
		"--session-id", "security-exec-disabled",
		runner,
	})
	if err == nil {
		t.Fatalf("expected error, got nil\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "loading workflow") || !strings.Contains(err.Error(), "WithExecEvaluatorEnabled") {
		t.Fatalf("err = %v, want exec opt-in failure", err)
	}
}

func TestSecurityGateRunBlockedCallNeverReachesSubprocess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	workflowPath := writeTempFile(t, "workflow.yaml", gateReadThenEditWorkflow)
	markerPath := filepath.Join(t.TempDir(), "subprocess-ran")
	runner := writeGateRunnerScript(t, "cat >/dev/null\n: > "+markerPath+"\nprintf 'runner ok'\n")
	input := `{"tool_name":"Edit","tool_input":{"path":"src/app.go"}}`

	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input, []string{
		"--format", "raw",
		"--rules", rulesPath,
		"--workflow", workflowPath,
		"--session-id", "security-blocked-call",
		runner,
	})
	if err == nil || err.Error() != "exit 1" {
		t.Fatalf("err = %v, want exit 1\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if _, statErr := os.Stat(markerPath); !os.IsNotExist(statErr) {
		t.Fatalf("subprocess marker exists, blocked call reached child: %v", statErr)
	}
}

func TestSecurityGateRunMalformedSessionID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rulesPath := writeTempFile(t, "rules.yaml", validBundleYAML)
	runner := writeGateRunnerScript(t, "cat >/dev/null\nprintf 'runner ok'\n")
	input := `{"tool_name":"Read","tool_input":{"path":"README.md"}}`

	stdout, stderr, err := runGateCommand(t, newGateRunCmd(), input, []string{
		"--format", "raw",
		"--rules", rulesPath,
		"--session-id", "bad/session-id",
		runner,
	})
	if err == nil {
		t.Fatalf("expected error, got nil\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "session create") && !strings.Contains(err.Error(), "invalid session ID") {
		t.Fatalf("err = %v, want invalid session ID", err)
	}
}
