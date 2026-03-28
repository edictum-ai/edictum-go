package main

import (
	"strings"
	"testing"
)

const testCommandRulesYAML = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-command-rules
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      "args.path":
        contains_any: [".env"]
    then:
      action: block
      message: "Sensitive file blocked."

  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      "principal.ticket_ref":
        equals: ""
    then:
      action: block
      message: "Ticket required."

  - id: require-security-team
    type: pre
    tool: review_incident
    when:
      "principal.claims.team":
        not_equals: "security"
    then:
      action: block
      message: "Security team required."
`

func TestTestCmd_AllPass(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: allow-safe-read
    tool: read_file
    args:
      path: README.md
    expect: allow
  - id: block-sensitive-read
    tool: read_file
    args:
      path: /app/.env
    expect: block
    match_contract: block-env-reads
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "2/2 passed, 0 failed") {
		t.Fatalf("expected passing summary, got:\n%s", out)
	}
}

func TestTestCmd_WithFailure(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: wrong-expectation
    tool: read_file
    args:
      path: /app/.env
    expect: allow
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "1/1 passed") && !strings.Contains(out, "0/1 passed, 1 failed") {
		if !strings.Contains(out, "expected allow") {
			t.Fatalf("expected failure details, got:\n%s", out)
		}
	}
}

func TestTestCmd_MatchRule(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: match-rule
    tool: read_file
    args:
      path: /app/.env
    expect: block
    match_contract: block-env-reads
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "block-env-reads") {
		t.Fatalf("expected matching rule id in output, got:\n%s", out)
	}
}

func TestTestCmd_MatchRuleWrongID(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: wrong-rule
    tool: read_file
    args:
      path: /app/.env
    expect: block
    match_contract: some-other-rule
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "wrong-rule:") || !strings.Contains(out, "block-env-reads") {
		t.Fatalf("expected rule ID mismatch output, got:\n%s", out)
	}
}

func TestTestCmd_PrincipalWithTicket(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: deploy-with-ticket
    tool: deploy_service
    args:
      service: api
    principal:
      role: sre
      ticket_ref: INC-123
    expect: allow
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "1/1 passed, 0 failed") {
		t.Fatalf("expected passing ticket case, got:\n%s", out)
	}
}

func TestTestCmd_PrincipalWithClaims(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: claims-field-ignored
    tool: review_incident
    args:
      id: inc-123
    principal:
      claims:
        team: security
    expect: allow
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "claims-field-ignored") || !strings.Contains(out, "ALLOW") {
		t.Fatalf("expected allow output, got:\n%s", out)
	}
}

func TestTestCmd_InvalidRules(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", invalidYAMLSyntax)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: anything
    tool: read_file
    args:
      path: README.md
    expect: allow
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (go run wrapper for CLI exit 2)\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "building guard") || !strings.Contains(out, "exit status 2") {
		t.Fatalf("expected rules error, got:\n%s", out)
	}
}

func TestTestCmd_NoCasesKey(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `not_cases:
  - id: ignored
    tool: read_file
    expect: allow
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "0/0 passed, 0 failed") {
		t.Fatalf("expected empty cases summary, got:\n%s", out)
	}
}

func TestTestCmd_NotAList(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases: not-a-list
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (go run wrapper for CLI exit 2)\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "parsing cases file") || !strings.Contains(out, "exit status 2") {
		t.Fatalf("expected parse error, got:\n%s", out)
	}
}

func TestTestCmd_MissingToolField(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: missing-tool
    args:
      path: README.md
    expect: allow
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "missing-tool") {
		t.Fatalf("expected case id in output, got:\n%s", out)
	}
}

func TestTestCmd_MissingExpectField(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: missing-expect
    tool: read_file
    args:
      path: README.md
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "missing-expect") {
		t.Fatalf("expected case id in output, got:\n%s", out)
	}
}

func TestTestCmd_MixedPassAndFail(t *testing.T) {
	bundle := writeTempFile(t, "rules.yaml", testCommandRulesYAML)
	cases := writeTempFile(t, "cases.yaml", `cases:
  - id: pass-case
    tool: read_file
    args:
      path: README.md
    expect: allow
  - id: fail-case
    tool: read_file
    args:
      path: /app/.env
    expect: allow
`)

	code, out := runEdictum(t, "test", bundle, "--cases", cases)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "1/2 passed, 1 failed") {
		t.Fatalf("expected mixed summary, got:\n%s", out)
	}
}
