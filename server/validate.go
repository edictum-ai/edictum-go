package server

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
)

// safeIdentifierRe matches alphanumeric identifiers with dots, hyphens,
// and underscores. 1-128 characters, must start with alphanumeric.
var safeIdentifierRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

const (
	maxTags        = 64
	maxTagKeyLen   = 128
	maxTagValueLen = 256
)

// validateIdentifier checks that s is a safe identifier for use in URLs and headers.
func validateIdentifier(name, value string) error {
	if !safeIdentifierRe.MatchString(value) {
		return fmt.Errorf(
			"invalid %s: %q — must be 1-128 alphanumeric chars, hyphens, underscores, or dots",
			name, value,
		)
	}
	return nil
}

// validateTags checks tag count and key/value length limits.
func validateTags(tags map[string]string) error {
	if len(tags) > maxTags {
		return fmt.Errorf("too many tags (%d > %d); maximum is %d entries", len(tags), maxTags, maxTags)
	}
	for k, v := range tags {
		if len(k) > maxTagKeyLen {
			return fmt.Errorf("tag key too long (%d > %d): %q", len(k), maxTagKeyLen, k)
		}
		if len(v) > maxTagValueLen {
			return fmt.Errorf("tag value too long (%d > %d) for key %q", len(v), maxTagValueLen, k)
		}
	}
	return nil
}

// enforceTLS rejects plaintext HTTP to non-loopback hosts unless
// allowInsecure is true. Returns an error if the URL is not safe.
func enforceTLS(baseURL string, allowInsecure bool) error {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf(
			"unsupported URL scheme %q — only http and https are accepted",
			parsed.Scheme,
		)
	}
	if parsed.Scheme != "http" {
		return nil
	}
	host := parsed.Hostname()
	if isLoopback(host) {
		return nil
	}
	if !allowInsecure {
		return fmt.Errorf(
			"refusing plaintext HTTP connection to %s — use HTTPS or set AllowInsecure for non-production use",
			host,
		)
	}
	return nil
}

// isLoopback returns true for localhost, 127.0.0.1, and ::1.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
