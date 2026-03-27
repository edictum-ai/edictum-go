// Package skill provides a SKILL.md security scanner that detects
// dangerous patterns, obfuscation, credential access, and exfiltration
// indicators in markdown skill files.
package skill

// Severity represents the severity level of a security finding.
type Severity string

const (
	// SeverityCritical indicates an immediately exploitable security risk.
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh indicates a high-severity security risk.
	SeverityHigh Severity = "HIGH"
	// SeverityMedium indicates a medium-severity security risk.
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow indicates a low-severity security risk.
	SeverityLow Severity = "LOW"
	// SeverityInfo indicates an informational finding.
	SeverityInfo Severity = "INFO"
)
