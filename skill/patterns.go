package skill

import "regexp"

// Pattern defines a compiled regex pattern for security scanning,
// including its severity and category classification.
type Pattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity Severity
	Category string
}

// maxRegexInput is the maximum input length scanned by any single
// regex to prevent ReDoS. Inputs longer than this are truncated.
const maxRegexInput = 10_000

// truncateForRegex caps input length to maxRegexInput to prevent ReDoS.
func truncateForRegex(s string) string {
	if len(s) > maxRegexInput {
		return s[:maxRegexInput]
	}
	return s
}
