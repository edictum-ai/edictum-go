package workflow

import "testing"

func TestLoadString_ParsesWorkflow(t *testing.T) {
	def, err := LoadString(`apiVersion: edictum/v1
kind: Workflow
metadata:
  name: core-dev-process
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("specs/008.md")
        message: Read the workflow spec first
`)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	if def.Kind != "Workflow" {
		t.Fatalf("Kind = %q", def.Kind)
	}
	if len(def.Stages) != 1 || def.Stages[0].ID != "read-context" {
		t.Fatalf("unexpected stages: %+v", def.Stages)
	}
}

func TestLoadString_RejectsRulesetKind(t *testing.T) {
	_, err := LoadString(`apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: wrong
stages:
  - id: read-context
`)
	if err == nil {
		t.Fatal("expected kind validation error")
	}
}

func TestLoadString_RejectsInvalidRegexes(t *testing.T) {
	_, err := LoadString(`apiVersion: edictum/v1
kind: Workflow
metadata:
  name: invalid-regex
stages:
  - id: verify
    tools: [Bash]
    checks:
      - command_matches: "("
        message: broken
    exit:
      - condition: command_matches("(")
        message: broken gate
`)
	if err == nil {
		t.Fatal("expected regex validation error")
	}
}
