package yaml

import (
	"testing"

	"github.com/edictum-ai/edictum-go/envelope"
)

// --- 3.26-3.30: Selectors ---

func TestSelectorArgs(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{
		Args: map[string]any{
			"nested": map[string]any{
				"deep": map[string]any{"key": "found"},
			},
		},
	})
	r := EvaluateExpression(leaf("args.nested.deep.key", "equals", "found"), env, "")
	if !r.Matched {
		t.Fatal("expected match for nested args selector")
	}
}

func TestSelectorPrincipal(t *testing.T) {
	p := envelope.NewPrincipal(
		envelope.WithUserID("u-123"),
		envelope.WithRole("admin"),
		envelope.WithClaims(map[string]any{"team": "security"}),
	)
	env := makeEnv(t, envelope.CreateEnvelopeOptions{Principal: &p})
	r := EvaluateExpression(leaf("principal.user_id", "equals", "u-123"), env, "")
	if !r.Matched {
		t.Fatal("expected match for principal.user_id")
	}
	r = EvaluateExpression(leaf("principal.role", "equals", "admin"), env, "")
	if !r.Matched {
		t.Fatal("expected match for principal.role")
	}
	r = EvaluateExpression(leaf("principal.claims.team", "equals", "security"), env, "")
	if !r.Matched {
		t.Fatal("expected match for principal.claims.team")
	}
}

func TestSelectorPrincipalServiceID(t *testing.T) {
	p := envelope.NewPrincipal(
		envelope.WithServiceID("svc-001"),
		envelope.WithOrgID("org-42"),
		envelope.WithTicketRef("JIRA-100"),
	)
	env := makeEnv(t, envelope.CreateEnvelopeOptions{Principal: &p})
	r := EvaluateExpression(leaf("principal.service_id", "equals", "svc-001"), env, "")
	if !r.Matched {
		t.Fatal("expected match for principal.service_id")
	}
	r = EvaluateExpression(leaf("principal.org_id", "equals", "org-42"), env, "")
	if !r.Matched {
		t.Fatal("expected match for principal.org_id")
	}
	r = EvaluateExpression(leaf("principal.ticket_ref", "equals", "JIRA-100"), env, "")
	if !r.Matched {
		t.Fatal("expected match for principal.ticket_ref")
	}
}

func TestSelectorEnvVar(t *testing.T) {
	t.Setenv("EDICTUM_TEST_VAR", "true")
	t.Setenv("EDICTUM_TEST_NUM", "42")
	env := makeEnv(t, envelope.CreateEnvelopeOptions{})

	// Boolean coercion.
	r := EvaluateExpression(leaf("env.EDICTUM_TEST_VAR", "equals", true), env, "")
	if !r.Matched {
		t.Fatal("expected match for env var coerced to bool")
	}
	// Numeric coercion.
	r = EvaluateExpression(leaf("env.EDICTUM_TEST_NUM", "equals", 42), env, "")
	if !r.Matched {
		t.Fatal("expected match for env var coerced to int")
	}
	// Missing env var -> false.
	r = EvaluateExpression(leaf("env.NONEXISTENT_VAR_12345", "equals", "x"), env, "")
	if r.Matched {
		t.Fatal("expected false for missing env var")
	}
}

func TestSelectorMetadata(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{
		Metadata: map[string]any{
			"region": "us-east-1",
			"tags":   map[string]any{"env": "staging"},
		},
	})
	r := EvaluateExpression(leaf("metadata.region", "equals", "us-east-1"), env, "")
	if !r.Matched {
		t.Fatal("expected match for metadata.region")
	}
	r = EvaluateExpression(leaf("metadata.tags.env", "equals", "staging"), env, "")
	if !r.Matched {
		t.Fatal("expected match for nested metadata")
	}
}

func TestSelectorOutputText(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{})
	r := EvaluateExpression(leaf("output.text", "contains", "secret"), env, "the output has a secret in it")
	if !r.Matched {
		t.Fatal("expected match for output.text")
	}
	// Empty output -> missing -> false.
	r = EvaluateExpression(leaf("output.text", "contains", "secret"), env, "")
	if r.Matched {
		t.Fatal("expected false for empty output.text")
	}
}

// --- 3.31: Custom operators ---

func TestCustomOperators(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{
		Args: map[string]any{"level": 5},
	})
	ops := map[string]func(any, any) bool{
		"divisible_by": func(fv, ov any) bool {
			a, ok1 := fv.(int)
			b, ok2 := ov.(int)
			if !ok1 || !ok2 || b == 0 {
				return false
			}
			return a%b == 0
		},
	}
	r := EvaluateExpression(leaf("args.level", "divisible_by", 5), env, "",
		WithCustomOperators(ops))
	if !r.Matched {
		t.Fatal("expected custom operator to match")
	}
	r = EvaluateExpression(leaf("args.level", "divisible_by", 3), env, "",
		WithCustomOperators(ops))
	if r.Matched {
		t.Fatal("expected custom operator to not match")
	}
}

// --- 3.32: Custom selectors ---

func TestCustomSelectors(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{})
	sels := map[string]func(envelope.ToolEnvelope) map[string]any{
		"custom": func(_ envelope.ToolEnvelope) map[string]any {
			return map[string]any{"status": "active"}
		},
	}
	r := EvaluateExpression(leaf("custom.status", "equals", "active"), env, "",
		WithCustomSelectors(sels))
	if !r.Matched {
		t.Fatal("expected custom selector to match")
	}
	r = EvaluateExpression(leaf("custom.status", "equals", "inactive"), env, "",
		WithCustomSelectors(sels))
	if r.Matched {
		t.Fatal("expected custom selector to not match")
	}
}

// --- Additional: principal nil -> missing ---

func TestSelectorPrincipalNil(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{})
	r := EvaluateExpression(leaf("principal.user_id", "equals", "x"), env, "")
	if r.Matched {
		t.Fatal("expected false for nil principal")
	}
	if r.PolicyError {
		t.Fatal("expected no policy error for nil principal (missing field)")
	}
}

// --- Additional: environment selector ---

func TestSelectorEnvironment(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{Environment: "production"})
	r := EvaluateExpression(leaf("environment", "equals", "production"), env, "")
	if !r.Matched {
		t.Fatal("expected match for environment selector")
	}
}

// --- Additional: unknown operator -> PolicyError ---

func TestUnknownOperatorPolicyError(t *testing.T) {
	env := makeEnv(t, envelope.CreateEnvelopeOptions{ToolName: "Bash"})
	r := EvaluateExpression(leaf("tool.name", "bogus_op", "x"), env, "")
	if !r.PolicyError {
		t.Fatal("expected PolicyError for unknown operator")
	}
}

// --- Additional: env var float coercion ---

func TestEnvVarFloatCoercion(t *testing.T) {
	t.Setenv("EDICTUM_TEST_FLOAT", "3.14")
	env := makeEnv(t, envelope.CreateEnvelopeOptions{})
	r := EvaluateExpression(leaf("env.EDICTUM_TEST_FLOAT", "equals", 3.14), env, "")
	if !r.Matched {
		t.Fatal("expected match for env var coerced to float")
	}
}
