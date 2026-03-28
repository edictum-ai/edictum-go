package yaml

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/toolcall"
)

type invalidFixtureExpectation struct {
	ErrorContains string `json:"error_contains"`
}

func TestConformanceFixtures_Valid(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "valid", "*.yaml"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one valid fixture")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, _, err := LoadBundle(file)
			if err != nil {
				t.Fatalf("LoadBundle(%s): %v", file, err)
			}
			if _, err := Compile(data); err != nil {
				t.Fatalf("Compile(%s): %v", file, err)
			}
		})
	}
}

func TestConformanceFixtures_Invalid(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "invalid", "*.yaml"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one invalid fixture")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			sidecar := strings.TrimSuffix(file, ".yaml") + ".expected.json"
			raw, err := os.ReadFile(sidecar) //nolint:gosec // Sidecars are derived from testdata fixture filenames under version control.
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", sidecar, err)
			}
			var expected invalidFixtureExpectation
			if err := json.Unmarshal(raw, &expected); err != nil {
				t.Fatalf("Unmarshal(%s): %v", sidecar, err)
			}
			if expected.ErrorContains == "" {
				t.Fatalf("%s missing error_contains", sidecar)
			}

			_, _, err = LoadBundle(file)
			if err == nil {
				t.Fatalf("LoadBundle(%s): expected validation error", file)
			}
			if !strings.Contains(err.Error(), expected.ErrorContains) {
				t.Fatalf("LoadBundle(%s) error = %q, want substring %q", file, err, expected.ErrorContains)
			}
		})
	}
}

func TestConformanceFixtures_Security_SandboxCommandAllowlist(t *testing.T) {
	data, _, err := LoadBundle(filepath.Join("testdata", "security", "sandbox_command_allowlist.yaml"))
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	compiled, err := Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(compiled.SandboxContracts) != 1 {
		t.Fatalf("SandboxContracts len = %d, want 1", len(compiled.SandboxContracts))
	}

	passEnv := makeEnv(t, toolcall.CreateToolCallOptions{
		ToolName: "Bash",
		Args:     map[string]any{"command": "echo $HOME"},
	})
	decision, err := compiled.SandboxContracts[0].Check(t.Context(), passEnv)
	if err != nil {
		t.Fatalf("Check(passEnv): %v", err)
	}
	if !decision.Passed() {
		t.Fatalf("echo $HOME should remain allowlist-compatible, got %q", decision.Message())
	}

	denyEnv := makeEnv(t, toolcall.CreateToolCallOptions{
		ToolName: "Bash",
		Args:     map[string]any{"command": "echo $(rm -rf /)"},
	})
	decision, err = compiled.SandboxContracts[0].Check(t.Context(), denyEnv)
	if err != nil {
		t.Fatalf("Check(denyEnv): %v", err)
	}
	if decision.Passed() {
		t.Fatal("command substitution should be denied by sandbox allowlist extraction")
	}
}

func TestConformanceFixtures_Security_SymlinkMissingLeaf(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "security", "sandbox_symlink_missing_leaf.yaml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := strings.ReplaceAll(string(raw), "__LINK_ROOT__", linkDir)

	data, _, err := LoadBundleString(content)
	if err != nil {
		t.Fatalf("LoadBundleString: %v", err)
	}
	compiled, err := Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	env := makeEnv(t, toolcall.CreateToolCallOptions{
		ToolName: "ReadFile",
		Args:     map[string]any{"file_path": filepath.Join(linkDir, "nested", "file.txt")},
	})
	decision, err := compiled.SandboxContracts[0].Check(t.Context(), env)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Passed() {
		t.Fatalf("expected symlinked parent + missing leaf path to stay within sandbox, got %q", decision.Message())
	}
}
