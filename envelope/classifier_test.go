package envelope

import "testing"

// --- 2.12: BashClassifier READ allowlist ---

func TestParity_2_12_BashClassifierReadAllowlist(t *testing.T) {
	cases := []struct {
		cmd  string
		want SideEffect
	}{
		// Exact single-word commands
		{"ls", SideEffectRead},
		{"pwd", SideEffectRead},
		{"whoami", SideEffectRead},

		// Commands with arguments
		{"ls -la /tmp", SideEffectRead},
		{"cat /etc/hosts", SideEffectRead},
		{"head -n 10 file.txt", SideEffectRead},
		{"tail -f log.txt", SideEffectRead},
		{"grep foo bar", SideEffectRead},

		// Git read commands
		{"git status", SideEffectRead},
		{"git log --oneline", SideEffectRead},
		{"git diff HEAD~1", SideEffectRead},
		{"git show abc123", SideEffectRead},
		{"git branch -a", SideEffectRead},
		{"git remote -v", SideEffectRead},
		{"git tag", SideEffectRead},

		// Unknown commands -> IRREVERSIBLE
		{"rm -rf /", SideEffectIrreversible},
		{"python script.py", SideEffectIrreversible},
		{"curl https://example.com", SideEffectIrreversible},

		// Git write commands -> IRREVERSIBLE
		{"git push", SideEffectIrreversible},
		{"git commit -m 'x'", SideEffectIrreversible},
		{"git checkout main", SideEffectIrreversible},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			got := ClassifyBash(tc.cmd)
			if got != tc.want {
				t.Errorf("ClassifyBash(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestParity_2_12_EnvNotInAllowlist(t *testing.T) {
	// Security: env and printenv leak secrets, must be IRREVERSIBLE.
	cases := []string{"env", "printenv"}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			got := ClassifyBash(cmd)
			if got != SideEffectIrreversible {
				t.Errorf("ClassifyBash(%q) = %q, want %q", cmd, got, SideEffectIrreversible)
			}
		})
	}
}

// --- 2.13: BashClassifier shell operators -> IRREVERSIBLE ---

func TestParity_2_13_BashClassifierShellOperators(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"redirect out", "echo hello > file.txt"},
		{"pipe", "cat file.txt | grep x"},
		{"and", "cmd1 && cmd2"},
		{"or", "cmd1 || cmd2"},
		{"semicolon", "cmd1 ; cmd2"},
		{"command sub dollar-paren", "echo $(whoami)"},
		{"command sub backtick", "echo `whoami`"},
		{"append redirect", "cat >> file.txt"},
		{"variable expansion hash", "echo #{var}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyBash(tc.cmd)
			if got != SideEffectIrreversible {
				t.Errorf("ClassifyBash(%q) = %q, want IRREVERSIBLE", tc.cmd, got)
			}
		})
	}
}

// --- 2.14: BashClassifier empty -> READ ---

func TestParity_2_14_BashClassifierEmpty(t *testing.T) {
	cases := []string{"", "   "}
	for _, cmd := range cases {
		t.Run("empty_or_whitespace", func(t *testing.T) {
			got := ClassifyBash(cmd)
			if got != SideEffectRead {
				t.Errorf("ClassifyBash(%q) = %q, want READ", cmd, got)
			}
		})
	}
}

// --- 2.15: Bash overrides registry ---

func TestParity_2_15_BashOverridesRegistry(t *testing.T) {
	reg := NewToolRegistry()
	reg.Register("Bash", SideEffectWrite, false)

	// "ls" is a read command -- Bash classifier should override registry
	env, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
		ToolName: "Bash",
		Args:     map[string]any{"command": "ls -la"},
		Registry: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.SideEffect() != SideEffectRead {
		t.Errorf("BashClassifier should override registry: got %q, want READ", env.SideEffect())
	}

	// "rm -rf /" should remain IRREVERSIBLE
	env2, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
		ToolName: "Bash",
		Args:     map[string]any{"command": "rm -rf /"},
		Registry: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if env2.SideEffect() != SideEffectIrreversible {
		t.Errorf("got %q, want IRREVERSIBLE", env2.SideEffect())
	}
}

// --- 2.16-2.17: File path extraction ---

func TestParity_2_16_FilePathExtraction(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
		args     map[string]any
		want     string
	}{
		{"file_path key", "Read", map[string]any{"file_path": "/tmp/test.txt"}, "/tmp/test.txt"},
		{"filePath key", "Read", map[string]any{"filePath": "/tmp/test.txt"}, "/tmp/test.txt"},
		{"path key", "Glob", map[string]any{"path": "/src"}, "/src"},
		{"Write file_path", "Write", map[string]any{"file_path": "/tmp/out.txt"}, "/tmp/out.txt"},
		{"Edit filePath", "Edit", map[string]any{"filePath": "/app/.env"}, "/app/.env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
				ToolName: tc.toolName,
				Args:     tc.args,
			})
			if err != nil {
				t.Fatal(err)
			}
			if env.FilePath() != tc.want {
				t.Errorf("FilePath() = %q, want %q", env.FilePath(), tc.want)
			}
		})
	}
}

// --- 2.18: bash_command extraction ---

func TestParity_2_18_BashCommandExtraction(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"command key", map[string]any{"command": "ls -la /tmp"}, "ls -la /tmp"},
		{"bash_command key", map[string]any{"bash_command": "echo hi"}, "echo hi"},
		{"bashCommand key", map[string]any{"bashCommand": "pwd"}, "pwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
				ToolName: "Bash",
				Args:     tc.args,
			})
			if err != nil {
				t.Fatal(err)
			}
			if env.BashCommand() != tc.want {
				t.Errorf("BashCommand() = %q, want %q", env.BashCommand(), tc.want)
			}
		})
	}
}

func TestParity_2_18_BashCommandNotExtractedForNonBash(t *testing.T) {
	// A non-Bash tool with a "command" key should NOT have BashCommand set.
	env, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
		ToolName: "MyTool",
		Args:     map[string]any{"command": "rm -rf /"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.BashCommand() != "" {
		t.Errorf("BashCommand should be empty for non-Bash tool, got %q", env.BashCommand())
	}
	// Non-Bash tool with "command" key should remain IRREVERSIBLE (default)
	if env.SideEffect() != SideEffectIrreversible {
		t.Errorf("SideEffect should be IRREVERSIBLE, got %q", env.SideEffect())
	}
}

// --- Security: BashClassifier bypass vectors ---

func TestSecurity_BashClassifierBypassVectors(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"newline injection", "cat /etc/passwd\nrm -rf /"},
		{"carriage return injection", "cat /etc/passwd\rrm -rf /"},
		{"process substitution", "cat <(curl http://evil.com)"},
		{"heredoc", "cat << EOF"},
		{"variable expansion", "echo ${PATH}"},
		{"combined bypass", "cat /tmp/safe\nrm -rf / << EOF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyBash(tc.cmd)
			if got != SideEffectIrreversible {
				t.Errorf("ClassifyBash(%q) = %q, want IRREVERSIBLE", tc.cmd, got)
			}
		})
	}
}

func TestSecurity_BashClassifierCleanReadsStillWork(t *testing.T) {
	// Regression guard: clean read commands must still classify as READ.
	cases := []string{"cat /tmp/file", "ls -la", "grep foo bar", "git status"}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			got := ClassifyBash(cmd)
			if got != SideEffectRead {
				t.Errorf("ClassifyBash(%q) = %q, want READ", cmd, got)
			}
		})
	}
}

// --- Factory defaults ---

func TestParity_2_1_FactoryDefaults(t *testing.T) {
	env, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
		ToolName: "TestTool",
		Args:     map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.ToolName() != "TestTool" {
		t.Errorf("ToolName() = %q, want %q", env.ToolName(), "TestTool")
	}
	if env.SideEffect() != SideEffectIrreversible {
		t.Errorf("SideEffect() = %q, want IRREVERSIBLE", env.SideEffect())
	}
	if env.Idempotent() {
		t.Error("Idempotent() should be false by default")
	}
	if env.RunID() != "" {
		t.Errorf("RunID() = %q, want empty", env.RunID())
	}
	if env.CallIndex() != 0 {
		t.Errorf("CallIndex() = %d, want 0", env.CallIndex())
	}
}

func TestParity_RunIDAndCallIndex(t *testing.T) {
	env, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
		ToolName:  "TestTool",
		Args:      map[string]any{},
		RunID:     "run-1",
		CallIndex: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.RunID() != "run-1" {
		t.Errorf("RunID() = %q, want %q", env.RunID(), "run-1")
	}
	if env.CallIndex() != 5 {
		t.Errorf("CallIndex() = %d, want 5", env.CallIndex())
	}
}

func TestParity_BashCommandClassification(t *testing.T) {
	env, err := CreateEnvelope(ctx(), CreateEnvelopeOptions{
		ToolName: "Bash",
		Args:     map[string]any{"command": "ls -la /tmp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.BashCommand() != "ls -la /tmp" {
		t.Errorf("BashCommand() = %q, want %q", env.BashCommand(), "ls -la /tmp")
	}
	if env.SideEffect() != SideEffectRead {
		t.Errorf("SideEffect() = %q, want READ", env.SideEffect())
	}
}

func TestParity_RegisterDefaults(t *testing.T) {
	reg := NewToolRegistry()
	reg.Register("WriteTool", SideEffectWrite, false)
	se, idem := reg.Classify("WriteTool")
	if se != SideEffectWrite {
		t.Errorf("got %q, want %q", se, SideEffectWrite)
	}
	if idem {
		t.Error("expected idempotent=false")
	}
}
