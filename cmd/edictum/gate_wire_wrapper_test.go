package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
