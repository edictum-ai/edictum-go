package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeminiHookScriptPreservesBlockingDecision(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required to execute the generated Gemini hook")
	}

	tests := []struct {
		name       string
		gateOutput string
		gateExit   int
		wantOutput string
		wantExit   int
	}{
		{"policy_block", `{"decision":"block","reason":"policy denied"}`, 1, `{"decision":"block","reason":"policy denied"}` + "\n", 2},
		{"gate_failure_payload", `{"decision":"block","reason":"gate failed"}`, 2, `{"decision":"block","reason":"gate failed"}` + "\n", 2},
		{"gate_failure_junk", "not json", 3, "not json\n", 2},
		{"gate_crash_without_payload", "", 3, "", 2},
		{"allow", `{}`, 0, "{}\n", 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, filepath.Join(dir, "edictum"), fmt.Sprintf("#!/bin/sh\ncat >/dev/null\nprintf '%%s' %s\nexit %d\n", shellQuote(test.gateOutput), test.gateExit))
			script := filepath.Join(dir, "edictum-gate.sh")
			writeExecutable(t, script, geminiHookScript)

			cmd := exec.Command("bash", script)
			cmd.Stdin = strings.NewReader(gateWireBlockInput("gemini"))
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &bytes.Buffer{}
			err := cmd.Run()

			gotExit := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				gotExit = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if gotExit != test.wantExit {
				t.Fatalf("exit code = %d, want %d", gotExit, test.wantExit)
			}
			if stdout.String() != test.wantOutput {
				t.Fatalf("stdout = %q, want %q", stdout.String(), test.wantOutput)
			}
			if test.wantExit == 2 && strings.HasPrefix(test.wantOutput, "{") {
				assertAcceptedWirePayload(t, stdout.Bytes(), gateWireContracts["gemini"])
			}
		})
	}
}

func TestOpenCodePluginFailsClosedOnGateProcessFailure(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the generated OpenCode plugin")
	}

	tests := []struct {
		name       string
		gateOutput string
		gateExit   int
		want       string
	}{
		{"policy_block", `{"allow":false,"reason":"policy denied"}`, 0, "blocked\n"},
		{"gate_failure_without_payload", "", 3, "blocked\n"},
		{"gate_failure_with_allow_payload", `{"allow":true}`, 3, "blocked\n"},
		{"allow", `{"allow":true}`, 0, "allowed\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, filepath.Join(dir, "edictum"), fmt.Sprintf("#!/bin/sh\ncat >/dev/null\nprintf '%%s' %s\nexit %d\n", shellQuote(test.gateOutput), test.gateExit))
			if err := os.WriteFile(filepath.Join(dir, "edictum-gate.mjs"), []byte(opencodePluginContent), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := `import { EdictumGate } from "./edictum-gate.mjs";
const plugin = await EdictumGate({ directory: process.cwd() });
try {
  await plugin["tool.execute.before"]({ tool: "bash" }, { args: { command: "echo ok" } });
  console.log("allowed");
} catch (_) {
  console.log("blocked");
}
`
			runnerPath := filepath.Join(dir, "runner.mjs")
			if err := os.WriteFile(runnerPath, []byte(runner), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(node, runnerPath)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("running generated plugin: %v\n%s", err, output)
			}
			if string(output) != test.want {
				t.Fatalf("plugin result = %q, want %q", output, test.want)
			}
		})
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\"'\"'`) + "'"
}
