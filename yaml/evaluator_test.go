package yaml

import (
	"context"
	"strings"
	"testing"

	"github.com/edictum-ai/edictum-go/toolcall"
)

// makeEnv creates a test ToolCall with common defaults.
func makeEnv(t *testing.T, opts toolcall.CreateToolCallOptions) toolcall.ToolCall {
	t.Helper()
	if opts.ToolName == "" {
		opts.ToolName = "TestTool"
	}
	env, err := toolcall.CreateToolCall(context.Background(), opts)
	if err != nil {
		t.Fatalf("CreateToolCall: %v", err)
	}
	return env
}

// leaf builds a single-operator leaf expression.
func leaf(selector, op string, value any) map[string]any {
	return map[string]any{selector: map[string]any{op: value}}
}

// --- 3.8-3.19: All 15 operators + exists ---

func TestOperatorEquals(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{ToolName: "Bash"})
	r := EvaluateExpression(leaf("tool.name", "equals", "Bash"), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("tool.name", "equals", "Other"), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorNotEquals(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{ToolName: "Bash"})
	r := EvaluateExpression(leaf("tool.name", "not_equals", "Other"), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("tool.name", "not_equals", "Bash"), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorIn(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{ToolName: "Bash"})
	r := EvaluateExpression(leaf("tool.name", "in", []any{"Bash", "Read"}), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("tool.name", "in", []any{"Write", "Edit"}), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorNotIn(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{ToolName: "Bash"})
	r := EvaluateExpression(leaf("tool.name", "not_in", []any{"Write", "Edit"}), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("tool.name", "not_in", []any{"Bash", "Read"}), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorContains(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"cmd": "rm -rf /tmp"},
	})
	r := EvaluateExpression(leaf("args.cmd", "contains", "rm -rf"), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.cmd", "contains", "mkdir"), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorContainsAny(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"cmd": "rm -rf /tmp"},
	})
	r := EvaluateExpression(leaf("args.cmd", "contains_any", []any{"mkdir", "rm -rf"}), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.cmd", "contains_any", []any{"mkdir", "ls"}), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorStartsWith(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"path": "/etc/passwd"},
	})
	r := EvaluateExpression(leaf("args.path", "starts_with", "/etc"), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.path", "starts_with", "/usr"), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorEndsWith(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"file": "config.yaml"},
	})
	r := EvaluateExpression(leaf("args.file", "ends_with", ".yaml"), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.file", "ends_with", ".json"), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorMatches(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"cmd": "curl https://example.com"},
	})
	r := EvaluateExpression(leaf("args.cmd", "matches", `https?://`), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.cmd", "matches", `^ftp://`), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorMatchesAny(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"cmd": "curl https://example.com"},
	})
	r := EvaluateExpression(leaf("args.cmd", "matches_any", []any{`^ftp://`, `https?://`}), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.cmd", "matches_any", []any{`^ftp://`, `^ssh://`}), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorGt(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"count": 10},
	})
	r := EvaluateExpression(leaf("args.count", "gt", 5), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.count", "gt", 10), env, "")
	if r.Matched {
		t.Fatal("expected no match for equal values")
	}
}

func TestOperatorGte(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"count": 10},
	})
	r := EvaluateExpression(leaf("args.count", "gte", 10), env, "")
	if !r.Matched {
		t.Fatal("expected match for equal values")
	}
	r = EvaluateExpression(leaf("args.count", "gte", 11), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorLt(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"count": 5},
	})
	r := EvaluateExpression(leaf("args.count", "lt", 10), env, "")
	if !r.Matched {
		t.Fatal("expected match")
	}
	r = EvaluateExpression(leaf("args.count", "lt", 5), env, "")
	if r.Matched {
		t.Fatal("expected no match for equal values")
	}
}

func TestOperatorLte(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"count": 5},
	})
	r := EvaluateExpression(leaf("args.count", "lte", 5), env, "")
	if !r.Matched {
		t.Fatal("expected match for equal values")
	}
	r = EvaluateExpression(leaf("args.count", "lte", 4), env, "")
	if r.Matched {
		t.Fatal("expected no match")
	}
}

func TestOperatorExists(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"key": "value"},
	})
	// Field present, exists: true -> match.
	r := EvaluateExpression(leaf("args.key", "exists", true), env, "")
	if !r.Matched {
		t.Fatal("expected match: field exists")
	}
	// Field present, exists: false -> no match.
	r = EvaluateExpression(leaf("args.key", "exists", false), env, "")
	if r.Matched {
		t.Fatal("expected no match: field exists but asked for false")
	}
	// Field absent, exists: false -> match.
	r = EvaluateExpression(leaf("args.missing", "exists", false), env, "")
	if !r.Matched {
		t.Fatal("expected match: field missing with exists: false")
	}
	// Field absent, exists: true -> no match.
	r = EvaluateExpression(leaf("args.missing", "exists", true), env, "")
	if r.Matched {
		t.Fatal("expected no match: field missing with exists: true")
	}
}

// --- 3.20: Regex input cap 10k ---

func TestRegexInputCap10k(t *testing.T) {
	// Build a string longer than MaxRegexInput.
	long := strings.Repeat("a", MaxRegexInput+500)
	// Place a match marker beyond the cap boundary.
	long += "MARKER"
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"text": long},
	})
	// Should NOT match because MARKER is past the 10k cap.
	r := EvaluateExpression(leaf("args.text", "matches", "MARKER"), env, "")
	if r.Matched {
		t.Fatal("expected no match: regex input should be truncated at 10k chars")
	}
	// A pattern matching within the first 10k chars should work.
	r = EvaluateExpression(leaf("args.text", "matches", "^a+"), env, "")
	if !r.Matched {
		t.Fatal("expected match within first 10k chars")
	}
}

// --- 3.21-3.23: Boolean AST ---

func TestBooleanAll(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		ToolName: "Bash",
		Args:     map[string]any{"cmd": "rm -rf /"},
	})
	expr := map[string]any{
		"all": []any{
			leaf("tool.name", "equals", "Bash"),
			leaf("args.cmd", "contains", "rm -rf"),
		},
	}
	r := EvaluateExpression(expr, env, "")
	if !r.Matched {
		t.Fatal("expected all to match")
	}
	// One false -> all is false.
	expr = map[string]any{
		"all": []any{
			leaf("tool.name", "equals", "Bash"),
			leaf("args.cmd", "contains", "mkdir"),
		},
	}
	r = EvaluateExpression(expr, env, "")
	if r.Matched {
		t.Fatal("expected all to fail when one child fails")
	}
}

func TestBooleanAny(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{ToolName: "Bash"})
	expr := map[string]any{
		"any": []any{
			leaf("tool.name", "equals", "Read"),
			leaf("tool.name", "equals", "Bash"),
		},
	}
	r := EvaluateExpression(expr, env, "")
	if !r.Matched {
		t.Fatal("expected any to match")
	}
	// All false -> any is false.
	expr = map[string]any{
		"any": []any{
			leaf("tool.name", "equals", "Read"),
			leaf("tool.name", "equals", "Write"),
		},
	}
	r = EvaluateExpression(expr, env, "")
	if r.Matched {
		t.Fatal("expected any to fail when all children fail")
	}
}

func TestBooleanNot(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{ToolName: "Bash"})
	expr := map[string]any{
		"not": leaf("tool.name", "equals", "Read"),
	}
	r := EvaluateExpression(expr, env, "")
	if !r.Matched {
		t.Fatal("expected not to invert false to true")
	}
	expr = map[string]any{
		"not": leaf("tool.name", "equals", "Bash"),
	}
	r = EvaluateExpression(expr, env, "")
	if r.Matched {
		t.Fatal("expected not to invert true to false")
	}
}

// --- 3.24: Missing fields -> false ---

func TestMissingFieldsFalse(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{})
	// args.nonexistent with equals -> false (not PolicyError).
	r := EvaluateExpression(leaf("args.nonexistent", "equals", "x"), env, "")
	if r.Matched {
		t.Fatal("expected false for missing field")
	}
	if r.PolicyError {
		t.Fatal("expected no policy error for missing field")
	}
}

// --- Multi-key leaf -> PolicyError ---

func TestEvalLeaf_MultiKeyReturnsError(t *testing.T) {
	expr := map[string]any{
		"args.name":  map[string]any{"equals": "test"},
		"args.other": map[string]any{"equals": "bad"},
	}
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		ToolName: "Test",
		Args:     map[string]any{"name": "test", "other": "bad"},
	})
	result := EvaluateExpression(expr, env, "")
	if !result.PolicyError {
		t.Fatal("expected PolicyError for multi-key leaf")
	}
}

// --- 3.25: Type mismatch -> PolicyError ---

func TestTypeMismatchPolicyError(t *testing.T) {
	env := makeEnv(t, toolcall.CreateToolCallOptions{
		Args: map[string]any{"count": 42},
	})
	// contains on an int -> PolicyError.
	r := EvaluateExpression(leaf("args.count", "contains", "x"), env, "")
	if !r.PolicyError {
		t.Fatal("expected PolicyError for type mismatch")
	}
	if !r.Matched {
		t.Fatal("expected Matched=true for PolicyError (fail-closed)")
	}
}
