package redaction

import (
	"reflect"
	"strings"
	"testing"
)

// --- 6.10: All 20 default sensitive keys detected ---

func TestPolicy_DefaultSensitiveKeys(t *testing.T) {
	p := NewPolicy()
	keys := []string{
		"password", "secret", "token", "api_key", "apikey",
		"api-key", "authorization", "auth", "credentials",
		"private_key", "privatekey", "access_token",
		"refresh_token", "client_secret", "connection_string",
		"database_url", "db_password", "ssh_key", "passphrase",
	}
	for _, k := range keys {
		if !p.IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = false, want true", k)
		}
	}
	// 19 exact keys in the default list. All must match.
	if len(keys) != 19 {
		t.Fatalf("test covers %d keys, want 19", len(keys))
	}
}

func TestPolicy_IsSensitiveKey_CaseInsensitive(t *testing.T) {
	p := NewPolicy()
	cases := []struct {
		key  string
		want bool
	}{
		{"PASSWORD", true},
		{"Api_Key", true},
		{"API-KEY", true},
		{"Authorization", true},
		{"CREDENTIALS", true},
	}
	for _, tc := range cases {
		if got := p.IsSensitiveKey(tc.key); got != tc.want {
			t.Errorf("IsSensitiveKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// --- Word-boundary matching (issue #127) ---

func TestPolicy_IsSensitiveKey_WordBoundary(t *testing.T) {
	p := NewPolicy()
	cases := []struct {
		key  string
		want bool
	}{
		// Exact matches.
		{"api_key", true},
		{"auth_token", true},
		{"my_secret_key", true},
		{"db_password", true},

		// Word-boundary: segment "token" matches.
		{"access_token", true},
		{"refresh_token", true},
		{"my_custom_token", true},

		// Word-boundary: segment "key" matches.
		{"api_key", true},
		{"ssh_key", true},

		// Word-boundary: segment "secret" matches.
		{"client_secret", true},

		// Word-boundary: segment "password" matches.
		{"user_password", true},

		// Word-boundary: segment "credential" matches.
		{"my_credential", true},

		// FALSE: "monkey" does NOT contain a segment matching "key".
		{"monkey", false},
		// FALSE: "bucket" segments are ["bucket"] -- no match.
		{"bucket", false},
		// FALSE: "socket" segments are ["socket"] -- no match.
		{"socket", false},
		// FALSE: "desktop" segments are ["desktop"] -- no match.
		{"desktop", false},
		// FALSE: "blanket" segments are ["blanket"] -- no match.
		{"blanket", false},
		// FALSE: no sensitive term in segments.
		{"username", false},
		{"data", false},
		{"url", false},
		{"name", false},
		{"hostname", false},
	}
	for _, tc := range cases {
		if got := p.IsSensitiveKey(tc.key); got != tc.want {
			t.Errorf("IsSensitiveKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// --- 6.11: Custom keys extend defaults ---

func TestPolicy_CustomKeysExtendDefaults(t *testing.T) {
	p := NewPolicy(WithSensitiveKeys([]string{"my_custom_field", "internal_id"}))

	// Custom keys work.
	if !p.IsSensitiveKey("my_custom_field") {
		t.Error("custom key my_custom_field not detected")
	}
	if !p.IsSensitiveKey("internal_id") {
		t.Error("custom key internal_id not detected")
	}

	// Defaults still work.
	if !p.IsSensitiveKey("password") {
		t.Error("default key password not detected")
	}
	if !p.IsSensitiveKey("api_key") {
		t.Error("default key api_key not detected")
	}
}

// --- 6.12-6.13: Bash redaction patterns ---

func TestPolicy_RedactBashCommand_ExportSecret(t *testing.T) {
	p := NewPolicy()
	cmd := "export MY_SECRET_KEY=abc123"
	got := p.RedactBashCommand(cmd)
	if strings.Contains(got, "abc123") {
		t.Fatalf("secret value not redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("REDACTED marker missing: %q", got)
	}
}

func TestPolicy_RedactBashCommand_ExportToken(t *testing.T) {
	p := NewPolicy()
	cmd := "export API_TOKEN=sk-12345"
	got := p.RedactBashCommand(cmd)
	if strings.Contains(got, "sk-12345") {
		t.Fatalf("token value not redacted: %q", got)
	}
}

func TestPolicy_RedactBashCommand_PasswordFlag(t *testing.T) {
	p := NewPolicy()
	cmd := "mysql -p mypassword -u root"
	got := p.RedactBashCommand(cmd)
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("password flag not redacted: %q", got)
	}
}

func TestPolicy_RedactBashCommand_URLCredentials(t *testing.T) {
	p := NewPolicy()
	cmd := "curl https://user:password123@example.com/api" //nolint:gosec // test data for redaction feature
	got := p.RedactBashCommand(cmd)
	if strings.Contains(got, "password123") {
		t.Fatalf("URL password not redacted: %q", got)
	}
}

// --- 6.14: Secret value detection patterns ---

func TestPolicy_DetectSecretValue(t *testing.T) {
	p := NewPolicy()
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"OpenAI", "sk-abcdefghijklmnopqrstuvwxyz", true},
		{"AWS", "AKIAIOSFODNN7EXAMPLE", true},
		{"JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload", true},
		{"GitHub", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true},
		{"Slack", "xoxb-123456789-abcdefghij", true},
		{"Normal", "hello world", false},
		{"Number", "42", false},
		{"Short", "sk-", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.DetectSecretValue(tc.value); got != tc.want {
				t.Errorf("DetectSecretValue(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestPolicy_DetectSecrets_Disabled(t *testing.T) {
	p := NewPolicy(WithDetectSecrets(false))
	args := map[string]any{"value": "sk-abcdefghijklmnopqrstuvwxyz"}
	got := p.RedactArgs(args)
	if got["value"] != "sk-abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("value redacted when detect_secrets disabled: %v", got["value"])
	}
}

// --- 6.15: Recursive redaction ---

func TestPolicy_RedactArgs_Basic(t *testing.T) {
	p := NewPolicy()
	args := map[string]any{
		"username": "alice",
		"password": "secret123",
		"data":     "safe",
	}
	got := p.RedactArgs(args)
	if got["username"] != "alice" {
		t.Errorf("username = %v, want alice", got["username"])
	}
	if got["password"] != "[REDACTED]" {
		t.Errorf("password = %v, want [REDACTED]", got["password"])
	}
	if got["data"] != "safe" {
		t.Errorf("data = %v, want safe", got["data"])
	}
}

func TestPolicy_RedactArgs_NestedMap(t *testing.T) {
	p := NewPolicy()
	args := map[string]any{
		"config": map[string]any{
			"api_key": "sk-abc123",
			"url":     "https://example.com",
		},
	}
	got := p.RedactArgs(args)
	cfg := got["config"].(map[string]any)
	if cfg["api_key"] != "[REDACTED]" {
		t.Errorf("nested api_key = %v, want [REDACTED]", cfg["api_key"])
	}
	if cfg["url"] != "https://example.com" {
		t.Errorf("nested url = %v, want original", cfg["url"])
	}
}

func TestPolicy_RedactArgs_Lists(t *testing.T) {
	p := NewPolicy()
	args := map[string]any{
		"items": []any{
			map[string]any{"token": "abc"},
			map[string]any{"name": "safe"},
		},
	}
	got := p.RedactArgs(args)
	items := got["items"].([]any)
	first := items[0].(map[string]any)
	second := items[1].(map[string]any)
	if first["token"] != "[REDACTED]" {
		t.Errorf("items[0].token = %v, want [REDACTED]", first["token"])
	}
	if second["name"] != "safe" {
		t.Errorf("items[1].name = %v, want safe", second["name"])
	}
}

func TestPolicy_RedactArgs_SecretValueDetection(t *testing.T) {
	p := NewPolicy()
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"OpenAI", "sk-abcdefghijklmnopqrstuvwxyz", "[REDACTED]"},
		{"AWS", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
		{"JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload", "[REDACTED]"},
		{"GitHub", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "[REDACTED]"},
		{"Slack", "xoxb-123456789-abcdefghij", "[REDACTED]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{"value": tc.value}
			got := p.RedactArgs(args)
			if got["value"] != tc.want {
				t.Errorf("value = %v, want %v", got["value"], tc.want)
			}
		})
	}
}

func TestPolicy_RedactArgs_NoFalsePositives(t *testing.T) {
	p := NewPolicy()
	args := map[string]any{"value": "hello world", "count": 42}
	got := p.RedactArgs(args)
	if got["value"] != "hello world" {
		t.Errorf("value = %v, want hello world", got["value"])
	}
	if got["count"] != 42 {
		t.Errorf("count = %v, want 42", got["count"])
	}
}

func TestPolicy_RedactArgs_DeeplyNested(t *testing.T) {
	p := NewPolicy()
	args := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"password": "deep_secret",
				"safe":     "ok",
			},
		},
	}
	got := p.RedactArgs(args)
	l1 := got["level1"].(map[string]any)
	l2 := l1["level2"].(map[string]any)
	if l2["password"] != "[REDACTED]" {
		t.Errorf("deeply nested password = %v, want [REDACTED]", l2["password"])
	}
	if l2["safe"] != "ok" {
		t.Errorf("deeply nested safe = %v, want ok", l2["safe"])
	}
}

// --- 6.16: String cap 1000 chars ---

func TestPolicy_RedactArgs_LongStringTruncation(t *testing.T) {
	p := NewPolicy()
	long := strings.Repeat("x", 1500)
	args := map[string]any{"data": long}
	got := p.RedactArgs(args)
	s := got["data"].(string)
	if len(s) != 1000 {
		t.Fatalf("truncated len = %d, want 1000", len(s))
	}
	if !strings.HasSuffix(s, "...") {
		t.Fatal("truncated string does not end with ...")
	}
}

func TestPolicy_RedactArgs_StringArgPasswordFlag(t *testing.T) {
	p := NewPolicy()
	got := p.RedactArgs(map[string]any{"command": "mysql --password hunter2"})
	if got["command"] != "mysql --password [REDACTED]" {
		t.Fatalf("command = %q", got["command"])
	}
}

func TestPolicy_RedactArgs_StringArgURLCredentials(t *testing.T) {
	p := NewPolicy()
	got := p.RedactArgs(map[string]any{"url": "https://admin:secret123@db.example.com"})
	if got["url"] != "https://admin:[REDACTED]@db.example.com" {
		t.Fatalf("url = %q", got["url"])
	}
}

func TestPolicy_RedactArgs_ExactlyMaxLength(t *testing.T) {
	p := NewPolicy()
	exact := strings.Repeat("x", 1000)
	args := map[string]any{"data": exact}
	got := p.RedactArgs(args)
	if got["data"] != exact {
		t.Fatal("string at exactly max length should not be truncated")
	}
}

// --- RedactResult ---

func TestPolicy_RedactResult_Short(t *testing.T) {
	p := NewPolicy()
	got := p.RedactResult("short result", 500)
	if got != "short result" {
		t.Fatalf("RedactResult = %q, want %q", got, "short result")
	}
}

func TestPolicy_RedactResult_Truncation(t *testing.T) {
	p := NewPolicy()
	long := strings.Repeat("x", 600)
	got := p.RedactResult(long, 500)
	if len(got) != 500 {
		t.Fatalf("RedactResult len = %d, want 500", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatal("truncated result does not end with ...")
	}
}

func TestPolicy_RedactResult_DefaultMaxLength(t *testing.T) {
	p := NewPolicy()
	long := strings.Repeat("x", 600)
	got := p.RedactResult(long, 0)
	if len(got) != 500 {
		t.Fatalf("RedactResult with 0 maxLength: len = %d, want 500", len(got))
	}
}

// --- 6.17: Payload cap 32KB ---

func TestPolicy_CapPayload_UnderLimit(t *testing.T) {
	p := NewPolicy()
	data := map[string]any{
		"tool_args": map[string]any{"key": "value"},
		"tool_name": "test",
	}
	got := p.CapPayload(data)
	if _, ok := got["_truncated"]; ok {
		t.Fatal("_truncated should not be set for small payloads")
	}
}

func TestPolicy_CapPayload_OverLimit(t *testing.T) {
	p := NewPolicy()
	data := map[string]any{
		"tool_args":      map[string]any{"key": strings.Repeat("x", 40000)},
		"result_summary": "big",
	}
	got := p.CapPayload(data)
	if got["_truncated"] != true {
		t.Fatal("_truncated should be true")
	}
	ta, ok := got["tool_args"].(map[string]any)
	if !ok {
		t.Fatalf("tool_args type = %T, want map", got["tool_args"])
	}
	want := map[string]any{"_redacted": "payload exceeded 32KB"}
	if !reflect.DeepEqual(ta, want) {
		t.Fatalf("tool_args = %v, want %v", ta, want)
	}
	if _, ok := got["result_summary"]; ok {
		t.Fatal("result_summary should be removed")
	}
}

// --- Nil and empty edge cases ---

func TestPolicy_RedactArgs_Nil(t *testing.T) {
	p := NewPolicy()
	got := p.RedactArgs(nil)
	if got != nil {
		t.Fatalf("RedactArgs(nil) = %v, want nil", got)
	}
}

func TestPolicy_RedactArgs_Empty(t *testing.T) {
	p := NewPolicy()
	got := p.RedactArgs(map[string]any{})
	if len(got) != 0 {
		t.Fatalf("RedactArgs(empty) len = %d, want 0", len(got))
	}
}

func TestPolicy_RedactBashCommand_Empty(t *testing.T) {
	p := NewPolicy()
	got := p.RedactBashCommand("")
	if got != "" {
		t.Fatalf("RedactBashCommand('') = %q, want empty", got)
	}
}
