package toolcall

import (
	"context"
	"testing"
)

func ctx() context.Context { return context.Background() }

// --- 2.1: Envelope immutability (unexported fields, Args returns copy) ---

func TestParity_2_1_EnvelopeImmutability(t *testing.T) {
	env, err := CreateToolCall(ctx(), CreateToolCallOptions{
		ToolName: "TestTool",
		Args:     map[string]any{"key": "value"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Args() must return a copy; mutating it must not affect the toolcall.
	argsCopy := env.Args()
	argsCopy["key"] = "mutated"

	got := env.Args()["key"]
	if got != "value" {
		t.Errorf("Args() leaked mutation: got %q, want %q", got, "value")
	}
}

// --- 2.2: Deep copy via CreateToolCall ---

func TestParity_2_2_DeepCopyIsolation(t *testing.T) {
	original := map[string]any{
		"nested": map[string]any{"key": "value"},
		"list":   []any{1, 2, 3},
	}
	env, err := CreateToolCall(ctx(), CreateToolCallOptions{
		ToolName: "TestTool",
		Args:     original,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mutate original after envelope creation
	original["nested"].(map[string]any)["key"] = "mutated"
	original["list"] = append(original["list"].([]any), 4)

	args := env.Args()
	nested := args["nested"].(map[string]any)
	if nested["key"] != "value" {
		t.Errorf("nested key leaked: got %q, want %q", nested["key"], "value")
	}
	list := args["list"].([]any)
	if len(list) != 3 {
		t.Errorf("list leaked: got len %d, want 3", len(list))
	}
}

func TestParity_2_2_MetadataDeepCopy(t *testing.T) {
	meta := map[string]any{"info": map[string]any{"nested": true}}
	env, err := CreateToolCall(ctx(), CreateToolCallOptions{
		ToolName: "TestTool",
		Args:     map[string]any{},
		Metadata: meta,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mutate original metadata
	meta["info"].(map[string]any)["nested"] = false

	got := env.Metadata()["info"].(map[string]any)["nested"]
	if got != true {
		t.Errorf("metadata leaked: got %v, want true", got)
	}
}

// --- 2.4: Principal claims deep-copied ---

func TestParity_2_4_PrincipalClaimsDeepCopy(t *testing.T) {
	claims := map[string]any{"role": "admin", "nested": map[string]any{"x": 1}}
	p := NewPrincipal(WithClaims(claims))

	// Mutate the original map
	claims["role"] = "hacker"
	claims["nested"].(map[string]any)["x"] = 999

	got := p.Claims()
	if got["role"] != "admin" {
		t.Errorf("claims leaked: got %q, want %q", got["role"], "admin")
	}

	// Claims() returns a copy — mutating it must not affect the principal
	c1 := p.Claims()
	c1["role"] = "mutated"
	c2 := p.Claims()
	if c2["role"] != "admin" {
		t.Errorf("Claims() returned live reference: got %q, want %q", c2["role"], "admin")
	}
}

// --- 2.5-2.8: Tool name validation ---

func TestParity_2_5_ToolNameEmpty(t *testing.T) {
	_, err := CreateToolCall(ctx(), CreateToolCallOptions{ToolName: ""})
	if err == nil {
		t.Fatal("expected error for empty tool name, got nil")
	}
}

func TestParity_2_6_ToolNameControlChars(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
	}{
		{"null byte", "tool\x00name"},
		{"newline", "tool\nname"},
		{"carriage return", "evil\rtool"},
		{"tab", "evil\ttool"},
		{"delete char", "evil\x7ftool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateToolCall(ctx(), CreateToolCallOptions{ToolName: tc.toolName})
			if err == nil {
				t.Fatalf("expected error for tool name %q, got nil", tc.toolName)
			}
		})
	}
}

func TestParity_2_7_ToolNamePathSeparators(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
	}{
		{"forward slash", "path/to/tool"},
		{"backslash", "path\\to\\tool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateToolCall(ctx(), CreateToolCallOptions{ToolName: tc.toolName})
			if err == nil {
				t.Fatalf("expected error for tool name %q, got nil", tc.toolName)
			}
		})
	}
}

func TestParity_2_8_ToolNameValidAccepted(t *testing.T) {
	names := []string{
		"Bash",
		"file.read",
		"google-search",
		"my_tool:v2",
		"Tool123",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			_, err := CreateToolCall(ctx(), CreateToolCallOptions{
				ToolName: name,
				Args:     map[string]any{},
			})
			if err != nil {
				t.Fatalf("valid tool name %q rejected: %v", name, err)
			}
		})
	}
}

// --- 2.9: SideEffect enum values ---

func TestParity_2_9_SideEffectValues(t *testing.T) {
	cases := []struct {
		se   SideEffect
		want string
	}{
		{SideEffectPure, "pure"},
		{SideEffectRead, "read"},
		{SideEffectWrite, "write"},
		{SideEffectIrreversible, "irreversible"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.se) != tc.want {
				t.Errorf("SideEffect %v: got %q, want %q", tc.se, string(tc.se), tc.want)
			}
		})
	}
}

// --- 2.10: Unregistered tool defaults to IRREVERSIBLE ---

func TestParity_2_10_UnregisteredToolIrreversible(t *testing.T) {
	env, err := CreateToolCall(ctx(), CreateToolCallOptions{
		ToolName: "UnknownTool",
		Args:     map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.SideEffect() != SideEffectIrreversible {
		t.Errorf("got %q, want %q", env.SideEffect(), SideEffectIrreversible)
	}
	if env.Idempotent() {
		t.Error("unregistered tool should not be idempotent")
	}
}

// --- 2.11: Registry classification ---

func TestParity_2_11_RegistryClassification(t *testing.T) {
	reg := NewToolRegistry()
	reg.Register("SafeTool", SideEffectPure, true)

	se, idem := reg.Classify("SafeTool")
	if se != SideEffectPure {
		t.Errorf("got %q, want %q", se, SideEffectPure)
	}
	if !idem {
		t.Error("expected idempotent=true")
	}

	// Unregistered
	se2, idem2 := reg.Classify("Unknown")
	if se2 != SideEffectIrreversible {
		t.Errorf("unregistered: got %q, want %q", se2, SideEffectIrreversible)
	}
	if idem2 {
		t.Error("unregistered should not be idempotent")
	}
}

func TestParity_2_11_RegistryWithEnvelope(t *testing.T) {
	reg := NewToolRegistry()
	reg.Register("MyTool", SideEffectRead, true)

	env, err := CreateToolCall(ctx(), CreateToolCallOptions{
		ToolName: "MyTool",
		Args:     map[string]any{},
		Registry: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.SideEffect() != SideEffectRead {
		t.Errorf("got %q, want %q", env.SideEffect(), SideEffectRead)
	}
	if !env.Idempotent() {
		t.Error("expected idempotent=true")
	}
}
