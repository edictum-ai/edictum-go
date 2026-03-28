package sandbox

import (
	"net/url"
	"strings"

	"github.com/edictum-ai/edictum-go/toolcall"
)

// ExtractURLs extracts URL strings from envelope args (shell-aware).
//
// For values that contain "://" but are not bare URLs (e.g. command
// strings like "curl https://evil.com"), tokenizes the value and
// extracts individual URL tokens.
func ExtractURLs(env toolcall.ToolCall) []string {
	var urls []string
	seen := make(map[string]bool)

	addURL := func(u string) {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	args := env.Args()
	for _, value := range args {
		s, ok := value.(string)
		if !ok || !strings.Contains(s, "://") {
			continue
		}
		// Try as a bare URL first
		if extractHostname(s) != "" {
			addURL(s)
		} else {
			// Not a bare URL -- tokenize and scan for embedded URLs
			for _, token := range tokenizeCommand(s) {
				if strings.Contains(token, "://") && extractHostname(token) != "" {
					addURL(token)
				}
			}
		}
	}
	return urls
}

// extractHostname parses a URL and returns its hostname, or "" on failure.
func extractHostname(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
