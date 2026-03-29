package pipeline_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func makeEnvelopeWithRegistry(t *testing.T, tool string, args map[string]any, se toolcall.SideEffect) toolcall.ToolCall {
	t.Helper()
	reg := toolcall.NewToolRegistry()
	reg.Register(tool, se, false)
	env, err := toolcall.CreateToolCall(context.Background(), toolcall.CreateToolCallOptions{
		ToolName: tool, Args: args, Registry: reg,
	})
	if err != nil {
		t.Fatalf("CreateToolCall: %v", err)
	}
	return env
}

func TestPostExecute_SuccessNoPostconditions(t *testing.T) {
	p := pipeline.New(defaultProvider())
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PostExecute(context.Background(), env, "ok", true)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.ToolSuccess {
		t.Fatal("expected tool_success=true")
	}
	if !dec.PostconditionsPassed {
		t.Fatal("expected postconditions_passed=true")
	}
	if len(dec.Warnings) != 0 {
		t.Fatalf("expected 0 warnings, got %d", len(dec.Warnings))
	}
}

func TestPostExecute_PostconditionFailurePureTool(t *testing.T) {
	prov := defaultProvider()
	prov.postconditions = []rule.Postcondition{{
		Name: "check_result", Tool: "TestTool",
		Check: func(_ context.Context, _ toolcall.ToolCall, result any) (rule.Decision, error) {
			if result != "expected" {
				return rule.Fail("Unexpected result"), nil
			}
			return rule.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "TestTool", nil, toolcall.SideEffectPure)
	dec, err := p.PostExecute(context.Background(), env, "wrong", true)
	if err != nil {
		t.Fatal(err)
	}
	if dec.PostconditionsPassed {
		t.Fatal("expected postconditions_passed=false")
	}
	if len(dec.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(dec.Warnings))
	}
	if !strings.Contains(strings.ToLower(dec.Warnings[0]), "consider retrying") {
		t.Fatalf("expected 'consider retrying' in warning, got %q", dec.Warnings[0])
	}
}

func TestPostExecute_PostconditionFailureWriteTool(t *testing.T) {
	prov := defaultProvider()
	prov.postconditions = []rule.Postcondition{{
		Name: "check_write", Tool: "WriteTool",
		Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
			return rule.Fail("Write verification failed"), nil
		},
	}}
	p := pipeline.New(prov)
	// WriteTool defaults to IRREVERSIBLE (unregistered)
	env := makeEnvelope(t, "WriteTool", nil)
	dec, err := p.PostExecute(context.Background(), env, "result", true)
	if err != nil {
		t.Fatal(err)
	}
	if dec.PostconditionsPassed {
		t.Fatal("expected postconditions_passed=false")
	}
	if !strings.Contains(strings.ToLower(dec.Warnings[0]), "assess before proceeding") {
		t.Fatalf("expected 'assess before proceeding', got %q", dec.Warnings[0])
	}
}

func TestPostExecute_AfterHooksCalled(t *testing.T) {
	var called []any
	prov := defaultProvider()
	prov.hooks = []pipeline.HookRegistration{{
		Phase: "after", Tool: "*", Name: "tracker",
		After: func(_ context.Context, _ toolcall.ToolCall, result any) error {
			called = append(called, result)
			return nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelope(t, "TestTool", nil)
	_, err := p.PostExecute(context.Background(), env, "the_result", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(called) != 1 || called[0] != "the_result" {
		t.Fatalf("expected after hook called with 'the_result', got %v", called)
	}
}

func TestPostExecute_ToolFailureReported(t *testing.T) {
	p := pipeline.New(defaultProvider())
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PostExecute(context.Background(), env, "Error: failed", false)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ToolSuccess {
		t.Fatal("expected tool_success=false")
	}
}

// --- Postcondition effects (parity 1.12-1.16) ---

func TestPostExecute_RedactEffectPureTool(t *testing.T) {
	prov := defaultProvider()
	prov.postconditions = []rule.Postcondition{{
		Name: "redact_ssn", Tool: "TestTool", Effect: "redact",
		RedactPatterns: []*regexp.Regexp{regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)},
		Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
			return rule.Fail("SSN found"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "TestTool", nil, toolcall.SideEffectPure)
	dec, err := p.PostExecute(context.Background(), env, "SSN: 123-45-6789", true)
	if err != nil {
		t.Fatal(err)
	}
	redacted, ok := dec.RedactedResponse.(string)
	if !ok {
		t.Fatalf("expected string response, got %T", dec.RedactedResponse)
	}
	if strings.Contains(redacted, "123-45-6789") {
		t.Fatal("SSN should be redacted")
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Fatal("expected [REDACTED] marker")
	}
}

func TestPostExecute_RedactEffectWriteFallsBackToWarn(t *testing.T) {
	prov := defaultProvider()
	prov.postconditions = []rule.Postcondition{{
		Name: "redact_attempt", Tool: "WriteTool", Effect: "redact",
		RedactPatterns: []*regexp.Regexp{regexp.MustCompile(`secret`)},
		Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
			return rule.Fail("found secret"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "WriteTool", nil, toolcall.SideEffectWrite)
	dec, err := p.PostExecute(context.Background(), env, "secret data", true)
	if err != nil {
		t.Fatal(err)
	}
	// WRITE tool: redact falls back to warn
	if dec.RedactedResponse != nil {
		t.Fatalf("WRITE tool should not be redacted, got %v", dec.RedactedResponse)
	}
	if !strings.Contains(strings.ToLower(dec.Warnings[0]), "assess before proceeding") {
		t.Fatalf("expected warn fallback, got %q", dec.Warnings[0])
	}
}

func TestPostExecute_DenyEffectPureTool(t *testing.T) {
	prov := defaultProvider()
	prov.postconditions = []rule.Postcondition{{
		Name: "suppress_output", Tool: "TestTool", Effect: "block",
		Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
			return rule.Fail("output not allowed"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "TestTool", nil, toolcall.SideEffectRead)
	dec, err := p.PostExecute(context.Background(), env, "sensitive data", true)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.OutputSuppressed {
		t.Fatal("expected output_suppressed=true")
	}
	redacted, ok := dec.RedactedResponse.(string)
	if !ok {
		t.Fatalf("expected string, got %T", dec.RedactedResponse)
	}
	if !strings.Contains(redacted, "[OUTPUT SUPPRESSED]") {
		t.Fatal("expected [OUTPUT SUPPRESSED] marker")
	}
}

func TestPostExecute_DenyEffectWriteFallsBackToWarn(t *testing.T) {
	prov := defaultProvider()
	prov.postconditions = []rule.Postcondition{{
		Name: "deny_attempt", Tool: "WriteTool", Effect: "block",
		Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
			return rule.Fail("not allowed"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "WriteTool", nil, toolcall.SideEffectIrreversible)
	dec, err := p.PostExecute(context.Background(), env, "result", true)
	if err != nil {
		t.Fatal(err)
	}
	if dec.OutputSuppressed {
		t.Fatal("IRREVERSIBLE tool should not suppress output")
	}
	if !strings.Contains(strings.ToLower(dec.Warnings[0]), "assess before proceeding") {
		t.Fatalf("expected warn fallback, got %q", dec.Warnings[0])
	}
}

func TestPostExecute_ObserveModePostcondition(t *testing.T) {
	prov := defaultProvider()
	prov.postconditions = []rule.Postcondition{{
		Name: "observe_post", Tool: "TestTool", Mode: "observe", Effect: "redact",
		Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
			return rule.Fail("would redact"), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "TestTool", nil, toolcall.SideEffectPure)
	dec, err := p.PostExecute(context.Background(), env, "data", true)
	if err != nil {
		t.Fatal(err)
	}
	// Observe mode: no redaction
	if dec.RedactedResponse != nil {
		t.Fatal("observe mode should not redact")
	}
	if len(dec.Warnings) != 1 {
		t.Fatalf("expected 1 observe warning, got %d", len(dec.Warnings))
	}
	if !strings.Contains(dec.Warnings[0], "[observe]") {
		t.Fatalf("expected [observe] in warning, got %q", dec.Warnings[0])
	}
}

func TestPostExecute_ObservePostconditionsEvaluated(t *testing.T) {
	prov := defaultProvider()
	prov.observePostconditions = []rule.Postcondition{{
		Name: "observe_scan", Tool: "TestTool", Effect: "redact",
		Check: func(_ context.Context, _ toolcall.ToolCall, resp any) (rule.Decision, error) {
			if strings.Contains(resp.(string), "secret") {
				return rule.Fail("secret detected in output"), nil
			}
			return rule.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "TestTool", nil, toolcall.SideEffectPure)
	dec, err := p.PostExecute(context.Background(), env, "contains secret data", true)
	if err != nil {
		t.Fatalf("PostExecute error: %v", err)
	}

	// Observe postcondition must appear in RulesEvaluated
	if len(dec.RulesEvaluated) != 1 {
		t.Fatalf("expected 1 rule evaluated, got %d", len(dec.RulesEvaluated))
	}
	rec := dec.RulesEvaluated[0]
	if rec["name"] != "observe_scan" {
		t.Fatalf("expected name=observe_scan, got %v", rec["name"])
	}
	if rec["passed"] != false {
		t.Fatal("expected passed=false for failing observe postcondition")
	}
	if rec["observed"] != true {
		t.Fatal("expected observed=true marker on observe postcondition")
	}

	// Observe mode must NOT redact or suppress output
	if dec.RedactedResponse != nil {
		t.Fatalf("observe postcondition must not redact, got %v", dec.RedactedResponse)
	}
	if dec.OutputSuppressed {
		t.Fatal("observe postcondition must not suppress output")
	}

	// Must produce an [observe] warning
	if len(dec.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(dec.Warnings), dec.Warnings)
	}
	if !strings.Contains(dec.Warnings[0], "[observe]") {
		t.Fatalf("expected [observe] in warning, got %q", dec.Warnings[0])
	}

	// PostconditionsPassed reflects the observe result in rules_evaluated
	if dec.PostconditionsPassed {
		t.Fatal("expected PostconditionsPassed=false (observe rule failed)")
	}
}

func TestPostExecute_ObservePostconditionPassDoesNotWarn(t *testing.T) {
	prov := defaultProvider()
	prov.observePostconditions = []rule.Postcondition{{
		Name: "observe_pass", Tool: "TestTool",
		Check: func(_ context.Context, _ toolcall.ToolCall, _ any) (rule.Decision, error) {
			return rule.Pass(), nil
		},
	}}
	p := pipeline.New(prov)
	env := makeEnvelopeWithRegistry(t, "TestTool", nil, toolcall.SideEffectPure)
	dec, err := p.PostExecute(context.Background(), env, "clean data", true)
	if err != nil {
		t.Fatal(err)
	}

	if len(dec.RulesEvaluated) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(dec.RulesEvaluated))
	}
	if dec.RulesEvaluated[0]["observed"] != true {
		t.Fatal("expected observed=true even for passing observe postcondition")
	}
	if len(dec.Warnings) != 0 {
		t.Fatalf("passing observe postcondition should produce no warnings, got %v", dec.Warnings)
	}
	if !dec.PostconditionsPassed {
		t.Fatal("expected PostconditionsPassed=true when observe passes")
	}
}

func TestParity_1_24_PostDecisionShape(t *testing.T) {
	p := pipeline.New(defaultProvider())
	env := makeEnvelope(t, "TestTool", nil)
	dec, err := p.PostExecute(context.Background(), env, "ok", true)
	if err != nil {
		t.Fatal(err)
	}

	_ = dec.ToolSuccess
	_ = dec.PostconditionsPassed
	_ = dec.Warnings
	_ = dec.RulesEvaluated
	_ = dec.PolicyError
	_ = dec.RedactedResponse
	_ = dec.OutputSuppressed
}
