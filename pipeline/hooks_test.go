package pipeline

import (
	"strings"
	"testing"
)

func TestHookDecisionAllow(t *testing.T) {
	d := AllowHook()
	if d.Result != HookResultAllow {
		t.Fatalf("expected Result=%q, got %q", HookResultAllow, d.Result)
	}
	if d.Reason != "" {
		t.Fatalf("expected empty Reason, got %q", d.Reason)
	}
}

func TestHookDecisionBlock(t *testing.T) {
	d := BlockHook("not allowed")
	if d.Result != HookResultBlock {
		t.Fatalf("expected Result=%q, got %q", HookResultBlock, d.Result)
	}
	if d.Reason != "not allowed" {
		t.Fatalf("expected Reason=%q, got %q", "not allowed", d.Reason)
	}
}

func TestHookDecisionBlockTruncation(t *testing.T) {
	tests := []struct {
		name       string
		inputLen   int
		wantLen    int
		wantSuffix string
		exact      bool
	}{
		{
			name:     "exact_500_no_truncation",
			inputLen: 500,
			wantLen:  500,
			exact:    true,
		},
		{
			name:       "501_truncated",
			inputLen:   501,
			wantLen:    500,
			wantSuffix: "...",
		},
		{
			name:       "600_truncated",
			inputLen:   600,
			wantLen:    500,
			wantSuffix: "...",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Repeat("x", tc.inputLen)
			d := BlockHook(input)

			if len(d.Reason) != tc.wantLen {
				t.Fatalf("expected len=%d, got %d", tc.wantLen, len(d.Reason))
			}
			if tc.exact && d.Reason != input {
				t.Fatal("expected reason to equal input exactly")
			}
			if tc.wantSuffix != "" && !strings.HasSuffix(d.Reason, tc.wantSuffix) {
				t.Fatalf("expected reason to end with %q", tc.wantSuffix)
			}
		})
	}
}

func TestHookResultValues(t *testing.T) {
	tests := []struct {
		result HookResult
		want   string
	}{
		{HookResultAllow, "allow"},
		{HookResultBlock, "block"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.result) != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, string(tc.result))
			}
		})
	}
}

func TestHookRegistrationHookName(t *testing.T) {
	tests := []struct {
		name string
		reg  HookRegistration
		want string
	}{
		{
			name: "empty_name_returns_anonymous",
			reg:  HookRegistration{},
			want: "anonymous",
		},
		{
			name: "non_empty_name_returned",
			reg:  HookRegistration{Name: "my-hook"},
			want: "my-hook",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.reg.HookName()
			if got != tc.want {
				t.Fatalf("HookName() = %q, want %q", got, tc.want)
			}
		})
	}
}
