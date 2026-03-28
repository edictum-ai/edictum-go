package main

import (
	"strings"
	"testing"
)

const checkBaseBundle = validateValidBundle
const checkTicketBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: ticket-bundle
defaults:
  mode: enforce
rules:
  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      "principal.ticket_ref":
        equals: ""
    then:
      action: block
      message: "Ticket required."
`

const checkRoleBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: role-bundle
defaults:
  mode: enforce
rules:
  - id: require-sre-role
    type: pre
    tool: deploy_service
    when:
      "principal.role":
        not_equals: "sre"
    then:
      action: block
      message: "SRE role required."
`

const checkEnvironmentBundle = `apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: environment-bundle
defaults:
  mode: enforce
rules:
  - id: only-staging
    type: pre
    tool: read_file
    when:
      environment:
        not_equals: "staging"
    then:
      action: block
      message: "Only staging is allowed."
`

func TestCheck_BlockedSensitiveRead(t *testing.T) {
	path := writeCLITestFile(t, checkBaseBundle)
	out, code := runCLI(t, "check", path, "--tool", "read_file", "--args", `{"path":"/app/.env"}`)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "blocked") || !strings.Contains(out, "block-env-reads") {
		t.Fatalf("expected blocked output mentioning rule id, got:\n%s", out)
	}
}

func TestCheck_AllowedSafeRead(t *testing.T) {
	path := writeCLITestFile(t, checkBaseBundle)
	out, code := runCLI(t, "check", path, "--tool", "read_file", "--args", `{"path":"README.md"}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "allowed") {
		t.Fatalf("expected allowed output, got:\n%s", out)
	}
}

func TestCheck_BlockedDestructiveBash(t *testing.T) {
	path := writeCLITestFile(t, checkBaseBundle)
	out, code := runCLI(t, "check", path, "--tool", "bash", "--args", `{"command":"rm -rf /tmp/data"}`)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "bash-safety") {
		t.Fatalf("expected blocking rule id in output, got:\n%s", out)
	}
}

func TestCheck_AllowedSafeBash(t *testing.T) {
	path := writeCLITestFile(t, checkBaseBundle)
	out, code := runCLI(t, "check", path, "--tool", "bash", "--args", `{"command":"ls -la"}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
}

func TestCheck_WithPrincipalRole(t *testing.T) {
	path := writeCLITestFile(t, checkRoleBundle)
	out, code := runCLI(t, "check", path, "--tool", "deploy_service", "--args", `{"service":"api"}`, "--principal-role", "sre")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "allowed") {
		t.Fatalf("expected allowed output, got:\n%s", out)
	}
}

func TestCheck_WithoutTicketBlocked(t *testing.T) {
	path := writeCLITestFile(t, checkTicketBundle)
	out, code := runCLI(t, "check", path, "--tool", "deploy_service", "--args", `{"service":"api"}`, "--principal-role", "sre")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(out, "require-ticket") && !strings.Contains(lower, "ticket") {
		t.Fatalf("expected ticket-related block, got:\n%s", out)
	}
}

func TestCheck_WithEnvironment(t *testing.T) {
	path := writeCLITestFile(t, checkEnvironmentBundle)
	out, code := runCLI(t, "check", path, "--tool", "read_file", "--args", `{"path":"safe.txt"}`, "--environment", "staging")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
}

func TestCheck_InvalidJSONArgs(t *testing.T) {
	path := writeCLITestFile(t, checkBaseBundle)
	out, code := runCLI(t, "check", path, "--tool", "read_file", "--args", "not valid json")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\noutput:\n%s", code, out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "json") && !strings.Contains(lower, "invalid") {
		t.Fatalf("expected JSON error, got:\n%s", out)
	}
}

func TestCheck_ShowsEvaluatedCount(t *testing.T) {
	path := writeCLITestFile(t, checkBaseBundle)
	out, code := runCLI(t, "check", path, "--tool", "read_file", "--args", `{"path":"safe.txt"}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "rules evaluated") {
		t.Fatalf("expected evaluated count in output, got:\n%s", out)
	}
}

func TestCheck_UnrelatedToolPasses(t *testing.T) {
	path := writeCLITestFile(t, checkBaseBundle)
	out, code := runCLI(t, "check", path, "--tool", "send_email", "--args", `{"to":"test@test.com"}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, out)
	}
}
