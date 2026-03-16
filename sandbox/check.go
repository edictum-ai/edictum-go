package sandbox

import (
	"path"
	"strings"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

// Check evaluates a tool call envelope against sandbox boundaries.
//
// Evaluation order:
//  1. Path checks: not_within denies first, then within requires match.
//  2. Command checks: first token must be in allowed commands list.
//  3. Domain checks: blocked_domains deny, then allowed_domains require match.
//
// Returns contract.Pass() if all checks pass, or contract.Fail(message)
// on the first violation.
func Check(env envelope.ToolEnvelope, cfg Config) (contract.Verdict, error) {
	msg := cfg.message()

	// --- Path checks ---
	if len(cfg.Within) > 0 || len(cfg.NotWithin) > 0 {
		paths := ExtractPaths(env)
		if len(paths) > 0 {
			// not_within: deny if any path matches an exclusion
			for _, p := range paths {
				if PathNotWithin(p, cfg.NotWithin) {
					return contract.Fail(msg), nil
				}
			}
			// within: every path must be within at least one allowed prefix
			if len(cfg.Within) > 0 {
				for _, p := range paths {
					if !PathWithin(p, cfg.Within) {
						return contract.Fail(msg), nil
					}
				}
			}
		}
	}

	// --- Command checks ---
	if len(cfg.AllowedCommands) > 0 {
		firstToken := ExtractCommand(env)
		if firstToken != "" {
			if !commandAllowed(firstToken, cfg.AllowedCommands) {
				return contract.Fail(msg), nil
			}
		}
	}

	// --- Domain checks ---
	urls := ExtractURLs(env)
	if len(urls) > 0 {
		for _, u := range urls {
			hostname := extractHostname(u)
			if hostname == "" {
				continue
			}
			// blocked_domains: deny if hostname matches any blocked pattern
			if len(cfg.BlockedDomains) > 0 && DomainMatches(hostname, cfg.BlockedDomains) {
				return contract.Fail(msg), nil
			}
			// allowed_domains: deny if hostname doesn't match any allowed pattern
			if len(cfg.AllowedDomains) > 0 && !DomainMatches(hostname, cfg.AllowedDomains) {
				return contract.Fail(msg), nil
			}
		}
	}

	return contract.Pass(), nil
}

// PathWithin reports whether path is within at least one of the allowed prefixes.
// Both the path and the prefix are compared after normalization. A path
// matches if it equals the prefix or starts with prefix + "/".
func PathWithin(p string, allowed []string) bool {
	for _, a := range allowed {
		norm := strings.TrimRight(a, "/")
		if p == norm || strings.HasPrefix(p, norm+"/") {
			return true
		}
	}
	return false
}

// PathNotWithin reports whether path matches any of the excluded prefixes.
// A path matches if it equals the prefix or starts with prefix + "/".
func PathNotWithin(p string, excluded []string) bool {
	for _, e := range excluded {
		norm := strings.TrimRight(e, "/")
		if p == norm || strings.HasPrefix(p, norm+"/") {
			return true
		}
	}
	return false
}

// DomainMatches reports whether hostname matches any of the domain patterns.
// Patterns support glob wildcards via path.Match (e.g. "*.googleapis.com").
func DomainMatches(hostname string, patterns []string) bool {
	for _, p := range patterns {
		if matched, err := path.Match(p, hostname); err == nil && matched {
			return true
		}
	}
	return false
}

// commandAllowed checks if cmd is in the allowed commands list.
func commandAllowed(cmd string, allowed []string) bool {
	for _, a := range allowed {
		if cmd == a {
			return true
		}
	}
	return false
}
