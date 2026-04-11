package yaml

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/toolcall"
	yamlv3 "gopkg.in/yaml.v3"
)

// extendsFixtureFile is the top-level structure of the extends-inheritance fixture.
type extendsFixtureFile struct {
	Suite    string                    `yaml:"suite"`
	Rulesets map[string]map[string]any `yaml:"rulesets"`
	Fixtures []extendsFixtureCase      `yaml:"fixtures"`
}

type extendsFixtureCase struct {
	ID          string          `yaml:"id"`
	Description string          `yaml:"description"`
	Contract    string          `yaml:"contract"` // name of ruleset in Rulesets
	Envelope    extendsEnvelope `yaml:"envelope"`
	Expected    extendsExpect   `yaml:"expected"`
}

type extendsEnvelope struct {
	ToolName  string         `yaml:"tool_name"`
	Arguments map[string]any `yaml:"arguments"`
}

type extendsExpect struct {
	Verdict         string `yaml:"verdict"` // "allowed" or "blocked" (fixture schema uses "denied" as an alias)
	MessageContains string `yaml:"message_contains"`
}

func TestV018ExtendsInheritanceFixtures(t *testing.T) {
	path, ok := resolveExtendsFixturePath()
	if !ok {
		t.Skip("extends-inheritance fixture not found; place edictum-schemas as sibling or set EDICTUM_SCHEMAS_DIR")
	}

	raw, err := os.ReadFile(path) //nolint:gosec // Test-only fixture path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var ff extendsFixtureFile
	if err := yamlv3.Unmarshal(raw, &ff); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, fc := range ff.Fixtures {
		t.Run(fc.ID, func(t *testing.T) {
			// Resolve extends: inheritance chain.
			bundle, err := ResolveExtendsFromRegistry(ff.Rulesets, fc.Contract)
			if err != nil {
				t.Fatalf("ResolveExtendsFromRegistry(%q): %v", fc.Contract, err)
			}

			// Compile the merged bundle.
			compiled, err := Compile(bundle)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}

			// Build the tool call from the envelope.
			env, err := toolcall.CreateToolCall(context.Background(), toolcall.CreateToolCallOptions{
				ToolName: fc.Envelope.ToolName,
				Args:     fc.Envelope.Arguments,
			})
			if err != nil {
				t.Fatalf("CreateToolCall: %v", err)
			}

			// Determine effective mode: observe mode = all allowed.
			if compiled.DefaultMode == "observe" {
				if fc.Expected.Verdict != "allowed" {
					t.Fatalf("[%s] observe mode: expected %q verdict but observe mode allows all", fc.ID, fc.Expected.Verdict)
				}
				return
			}

			// Evaluate all preconditions; first block wins.
			verdict := "allowed"
			message := ""
			for _, pre := range compiled.Preconditions {
				if pre.When != nil && !pre.When(context.Background(), env) {
					continue
				}
				if pre.Check == nil {
					continue
				}
				dec, err := pre.Check(context.Background(), env)
				if err != nil {
					t.Fatalf("[%s] Check: %v", fc.ID, err)
				}
				if !dec.Passed() {
					verdict = "blocked"
					message = dec.Message()
					break
				}
			}

			// The fixture schema uses "denied" as an alias for the canonical Go term "blocked".
			expectedVerdict := fc.Expected.Verdict
			if expectedVerdict == "denied" {
				expectedVerdict = "blocked"
			}
			if verdict != expectedVerdict {
				t.Fatalf("[%s] verdict = %q, want %q (message: %q)\n  description: %s",
					fc.ID, verdict, fc.Expected.Verdict, message, fc.Description)
			}
			if fc.Expected.MessageContains != "" && !strings.Contains(message, fc.Expected.MessageContains) {
				t.Fatalf("[%s] message = %q, want substring %q\n  description: %s",
					fc.ID, message, fc.Expected.MessageContains, fc.Description)
			}
		})
	}
}

func resolveExtendsFixturePath() (string, bool) {
	candidates := []string{}
	if dir := os.Getenv("EDICTUM_SCHEMAS_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "fixtures", "workflow-v0.18", "extends-inheritance.workflow-v0.18.yaml"))
	}
	candidates = append(candidates,
		"../../edictum-schemas/fixtures/workflow-v0.18/extends-inheritance.workflow-v0.18.yaml",
	)
	for _, c := range candidates {
		//nolint:gosec // Test-only fixture path from known env vars + fixed paths.
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, true
		}
	}
	return "", false
}
