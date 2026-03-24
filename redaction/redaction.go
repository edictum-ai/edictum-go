// Package redaction provides sensitive data masking for audit events.
package redaction

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Policy configures how sensitive data is redacted from audit events.
type Policy struct {
	sensitiveKeys  map[string]bool
	safeKeys       map[string]bool
	bashPatterns   []compiledPattern
	secretPatterns []*regexp.Regexp
	detectSecrets  bool
}

// compiledPattern is a pre-compiled regex with its replacement string.
type compiledPattern struct {
	re          *regexp.Regexp
	replacement string
}

// Option configures a Policy.
type Option func(*Policy)

// WithSensitiveKeys adds custom sensitive keys (extends defaults).
func WithSensitiveKeys(keys []string) Option {
	return func(p *Policy) {
		for _, k := range keys {
			p.sensitiveKeys[normalizeKey(k)] = true
		}
	}
}

// WithDetectSecrets enables or disables automatic secret value detection.
func WithDetectSecrets(detect bool) Option {
	return func(p *Policy) { p.detectSecrets = detect }
}

// NewPolicy creates a new Policy with the given options.
func NewPolicy(opts ...Option) *Policy {
	p := &Policy{
		sensitiveKeys: make(map[string]bool, len(defaultSensitiveKeys)),
		safeKeys:      make(map[string]bool, len(safeCompoundKeys)),
		detectSecrets: true,
	}
	for _, k := range defaultSensitiveKeys {
		p.sensitiveKeys[normalizeKey(k)] = true
	}
	for _, k := range safeCompoundKeys {
		p.safeKeys[normalizeKey(k)] = true
	}

	// Compile bash redaction patterns.
	p.bashPatterns = make([]compiledPattern, 0, len(bashRedactionPatterns))
	for _, bp := range bashRedactionPatterns {
		p.bashPatterns = append(p.bashPatterns, compiledPattern{
			re:          regexp.MustCompile(bp.pattern),
			replacement: bp.replacement,
		})
	}

	// Compile secret value patterns.
	p.secretPatterns = make([]*regexp.Regexp, 0, len(secretValuePatterns))
	for _, sp := range secretValuePatterns {
		p.secretPatterns = append(p.secretPatterns, regexp.MustCompile(sp))
	}

	for _, opt := range opts {
		opt(p)
	}
	return p
}

// IsSensitiveKey reports whether key should be treated as sensitive.
//
// Uses word-boundary matching per issue #127: the key is lowercased,
// split on "_" and "-", and each segment is checked for exact match
// against sensitive terms. This means "monkey" does NOT match "key",
// "bucket" does NOT match (no segment matches any term).
func (p *Policy) IsSensitiveKey(key string) bool {
	k := normalizeKey(key)
	if p.sensitiveKeys[k] {
		return true
	}
	if p.safeKeys[k] {
		return false
	}
	// Word-boundary matching: split on separators, check segments.
	segments := splitKeySegments(k)
	for _, seg := range segments {
		for _, term := range partialTerms {
			if seg == term {
				return true
			}
		}
	}
	return false
}

// splitKeySegments splits a key into word segments on "_" and "-".
func splitKeySegments(key string) []string {
	return strings.FieldsFunc(key, func(r rune) bool {
		return r == '_' || r == '-'
	})
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "-", "_"))
}

// DetectSecretValue reports whether value matches a known secret pattern.
func (p *Policy) DetectSecretValue(value string) bool {
	if len(value) > maxRegexInput {
		return false
	}
	for _, re := range p.secretPatterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// RedactArgs recursively redacts sensitive keys in args.
// Maps, slices, and string values are processed. Other types pass through.
// Returns nil for nil input.
func (p *Policy) RedactArgs(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	result, _ := p.redactValue(args).(map[string]any)
	return result
}

// redactValue recursively redacts a single value.
func (p *Policy) redactValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, v2 := range val {
			if p.IsSensitiveKey(k) {
				out[k] = redacted
			} else {
				out[k] = p.redactValue(v2)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = p.redactValue(item)
		}
		return out
	case string:
		if p.detectSecrets && p.DetectSecretValue(val) {
			return redacted
		}
		if p.detectSecrets {
			for _, bp := range p.bashPatterns {
				val = bp.re.ReplaceAllString(val, bp.replacement)
			}
		}
		if len(val) > maxStringLength {
			return val[:maxStringLength-3] + "..."
		}
		return val
	default:
		return v
	}
}

// RedactBashCommand applies bash redaction patterns to a command string.
func (p *Policy) RedactBashCommand(command string) string {
	if len(command) > maxRegexInput {
		command = command[:maxRegexInput]
	}
	result := command
	for _, bp := range p.bashPatterns {
		result = bp.re.ReplaceAllString(result, bp.replacement)
	}
	return result
}

// RedactResult truncates and redacts a result string.
// maxLength caps the returned string length. If maxLength <= 0,
// it defaults to 500.
func (p *Policy) RedactResult(result string, maxLength int) string {
	if maxLength <= 0 {
		maxLength = 500
	}
	r := result
	if len(r) > maxRegexInput {
		r = r[:maxRegexInput]
	}
	for _, bp := range p.bashPatterns {
		r = bp.re.ReplaceAllString(r, bp.replacement)
	}
	if len(r) > maxLength {
		r = r[:maxLength-3] + "..."
	}
	return r
}

// CapPayload caps total serialized size to 32KB.
// If the payload exceeds the limit, a new map is returned with
// tool_args and result_summary replaced by truncation markers.
// The original map is never mutated.
func (p *Policy) CapPayload(data map[string]any) map[string]any {
	serialized, err := json.Marshal(data)
	if err != nil || len(serialized) <= maxPayloadSize {
		return data
	}
	// Copy to avoid mutating the caller's map.
	out := make(map[string]any, len(data))
	for k, v := range data {
		out[k] = v
	}
	out["_truncated"] = true
	delete(out, "result_summary")
	out["tool_args"] = map[string]any{"_redacted": "payload exceeded 32KB"}
	return out
}
