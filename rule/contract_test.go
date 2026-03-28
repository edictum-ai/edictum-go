package rule

import (
	"reflect"
	"strings"
	"testing"
)

func TestVerdict(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		v := Pass()
		if !v.Passed() {
			t.Fatal("expected Passed() == true")
		}
		if v.Message() != "" {
			t.Fatalf("expected empty message, got %q", v.Message())
		}
		if v.Metadata() != nil {
			t.Fatalf("expected nil metadata, got %v", v.Metadata())
		}
	})

	t.Run("fail", func(t *testing.T) {
		v := Fail("something went wrong")
		if v.Passed() {
			t.Fatal("expected Passed() == false")
		}
		if v.Message() != "something went wrong" {
			t.Fatalf("expected %q, got %q", "something went wrong", v.Message())
		}
	})

	t.Run("fail_truncation", func(t *testing.T) {
		long := strings.Repeat("x", 600)
		v := Fail(long)
		if len(v.Message()) != 500 {
			t.Fatalf("expected message length 500, got %d", len(v.Message()))
		}
		if !strings.HasSuffix(v.Message(), "...") {
			t.Fatal("expected message to end with '...'")
		}
		if v.Message()[:497] != strings.Repeat("x", 497) {
			t.Fatal("expected first 497 chars to be preserved")
		}
	})

	t.Run("fail_exact_500", func(t *testing.T) {
		msg := strings.Repeat("x", 500)
		v := Fail(msg)
		if v.Message() != msg {
			t.Fatal("expected 500-char message to be kept verbatim")
		}
	})

	t.Run("fail_no_metadata", func(t *testing.T) {
		v := Fail("err")
		if v.Metadata() != nil {
			t.Fatalf("expected nil metadata, got %v", v.Metadata())
		}
	})

	t.Run("fail_with_metadata", func(t *testing.T) {
		v := Fail("err", map[string]any{"key1": "val1", "key2": 42})
		want := map[string]any{"key1": "val1", "key2": 42}
		if !reflect.DeepEqual(v.Metadata(), want) {
			t.Fatalf("metadata mismatch:\n  got:  %v\n  want: %v", v.Metadata(), want)
		}
	})
}

func TestPreconditionFields(t *testing.T) {
	p := Precondition{
		Name:   "no-rm",
		Tool:   "Bash",
		Mode:   "observe",
		Source: "precondition",
		Effect: "block",
	}
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"Name", p.Name, "no-rm"},
		{"Tool", p.Tool, "Bash"},
		{"Mode", p.Mode, "observe"},
		{"Source", p.Source, "precondition"},
		{"Effect", p.Effect, "block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestPostconditionFields(t *testing.T) {
	p := Postcondition{
		Name:   "redact-secrets",
		Tool:   "*",
		Mode:   "",
		Source: "postcondition",
		Effect: "redact",
	}
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"Name", p.Name, "redact-secrets"},
		{"Tool", p.Tool, "*"},
		{"Mode", p.Mode, ""},
		{"Source", p.Source, "postcondition"},
		{"Effect", p.Effect, "redact"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestSessionRuleFields(t *testing.T) {
	s := SessionRule{
		Name:   "rate-limit",
		Mode:   "observe",
		Source: "session_rule",
	}
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"Name", s.Name, "rate-limit"},
		{"Mode", s.Mode, "observe"},
		{"Source", s.Source, "session_rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}
