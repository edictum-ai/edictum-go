// Package redaction provides sensitive data masking for audit events.
package redaction

// Policy configures how sensitive data is redacted from audit events.
type Policy struct {
	sensitiveKeys    map[string]bool
	bashPatterns     []string
	secretPatterns   []string
	detectSecrets    bool
	maxPayloadSize   int
	maxRegexInput    int
	maxPatternLength int
}

// DefaultSensitiveKeys are keys that are always redacted.
var DefaultSensitiveKeys = []string{
	"password", "secret", "token", "api_key", "apikey",
	"credentials", "private_key", "privatekey", "access_token",
	"accesstoken", "refresh_token", "refreshtoken", "auth",
	"authorization", "cookie", "session", "ssn", "credit_card",
	"creditcard", "cvv",
}

const (
	// MaxPayloadSize is the maximum audit payload size (32KB).
	MaxPayloadSize = 32 * 1024
	// MaxStringLength is the maximum string length in audit events.
	MaxStringLength = 1000
	// MaxRegexInput is the maximum input length for regex matching.
	MaxRegexInput = 10000
	// MaxPatternLength is the maximum regex pattern length.
	MaxPatternLength = 10000
)

// Option configures a Policy.
type Option func(*Policy)

// WithSensitiveKeys adds custom sensitive keys (extends defaults).
func WithSensitiveKeys(keys []string) Option {
	return func(p *Policy) {
		for _, k := range keys {
			p.sensitiveKeys[k] = true
		}
	}
}

// WithDetectSecrets enables automatic secret value detection.
func WithDetectSecrets(detect bool) Option {
	return func(p *Policy) { p.detectSecrets = detect }
}

// NewPolicy creates a new RedactionPolicy with the given options.
func NewPolicy(opts ...Option) *Policy {
	p := &Policy{
		sensitiveKeys:    make(map[string]bool),
		detectSecrets:    true,
		maxPayloadSize:   MaxPayloadSize,
		maxRegexInput:    MaxRegexInput,
		maxPatternLength: MaxPatternLength,
	}
	for _, k := range DefaultSensitiveKeys {
		p.sensitiveKeys[k] = true
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}
