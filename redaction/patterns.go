package redaction

// defaultSensitiveKeys are keys that are always redacted.
// Matches Python edictum's RedactionPolicy.DEFAULT_SENSITIVE_KEYS exactly.
var defaultSensitiveKeys = []string{
	"password",
	"secret",
	"token",
	"api_key",
	"apikey",
	"api-key",
	"authorization",
	"auth",
	"credentials",
	"private_key",
	"privatekey",
	"access_token",
	"refresh_token",
	"client_secret",
	"connection_string",
	"database_url",
	"db_password",
	"ssh_key",
	"passphrase",
	"api_tokens",
	"db_passwords",
	"user_credentials",
	"oauth_secrets",
	"encryption_keys",
	"jwt_tokens",
}

// partialTerms are terms matched against word segments of a key.
// A key like "auth_token" splits into ["auth", "token"] and "token"
// matches, so it is redacted. "monkey" splits into ["monkey"] and
// no segment matches any term, so it is NOT redacted.
var partialTerms = []string{
	"token", "tokens", "key", "keys", "secret", "secrets",
	"password", "passwords", "credential", "credentials",
}

var safeCompoundKeys = []string{
	"max_tokens",
	"num_tokens",
	"input_tokens",
	"output_tokens",
	"total_tokens",
	"completion_tokens",
	"prompt_tokens",
	"cached_tokens",
	"reasoning_tokens",
	"audio_tokens",
	"cache_tokens",
	"sort_keys",
	"index_keys",
}

// bashRedactionPatterns are regex patterns for bash command redaction.
var bashRedactionPatterns = []struct {
	pattern     string
	replacement string
}{
	{`(export\s+\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*=)\S+`, `${1}[REDACTED]`},
	{`(-p\s*|--password[= ])\S+`, `${1}[REDACTED]`},
	{`(://\w+:)\S+(@)`, `${1}[REDACTED]${2}`},
}

// secretValuePatterns detect common secret formats in values.
var secretValuePatterns = []string{
	`^(sk-[a-zA-Z0-9]{20,})`,
	`^(AKIA[A-Z0-9]{16})`,
	`^(eyJ[a-zA-Z0-9_-]{20,}\.)`,
	`^(ghp_[a-zA-Z0-9]{36})`,
	`^(xox[bpas]-[a-zA-Z0-9-]{10,})`,
}

const (
	// maxPayloadSize is the maximum audit payload size (32KB).
	maxPayloadSize = 32 * 1024
	// maxStringLength is the maximum string length in audit events.
	maxStringLength = 1000
	// maxRegexInput is the maximum input length for regex matching.
	maxRegexInput = 10_000
	// redacted is the replacement string for sensitive values.
	redacted = "[REDACTED]"
)
