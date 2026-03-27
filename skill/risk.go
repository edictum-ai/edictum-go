package skill

// RiskTier represents the overall risk classification of a scanned skill.
type RiskTier string

const (
	// RiskCritical indicates one or more critical findings.
	RiskCritical RiskTier = "CRITICAL"
	// RiskHigh indicates one or more high-severity findings.
	RiskHigh RiskTier = "HIGH"
	// RiskMedium indicates one or more medium-severity findings.
	RiskMedium RiskTier = "MEDIUM"
	// RiskClean indicates no security findings.
	RiskClean RiskTier = "CLEAN"
)

// Finding represents a single security finding from the scanner.
type Finding struct {
	Severity Severity
	Category string
	Message  string
	Line     int
	Pattern  string // Which pattern matched
}

// ScanResult holds the complete results of scanning a skill.
type ScanResult struct {
	SkillName    string
	SkillPath    string
	RiskTier     RiskTier
	Findings     []Finding
	HasContracts bool // Whether contracts.yaml exists in the skill dir
}

// ClassifyRisk returns the highest severity tier from the given findings.
// Returns RiskClean if findings is empty.
func ClassifyRisk(findings []Finding) RiskTier {
	if len(findings) == 0 {
		return RiskClean
	}

	tier := RiskClean
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			return RiskCritical // short-circuit
		case SeverityHigh:
			tier = RiskHigh
		case SeverityMedium:
			if tier != RiskHigh {
				tier = RiskMedium
			}
		case SeverityLow, SeverityInfo:
			// Low and info findings do not affect the risk tier.
		}
	}
	return tier
}
