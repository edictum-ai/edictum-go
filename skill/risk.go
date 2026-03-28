package skill

// RiskTier represents the overall risk classification of a scanned skill.
type RiskTier string

const (
	// RiskCritical indicates one or more critical violations.
	RiskCritical RiskTier = "CRITICAL"
	// RiskHigh indicates one or more high-severity violations.
	RiskHigh RiskTier = "HIGH"
	// RiskMedium indicates one or more medium-severity violations.
	RiskMedium RiskTier = "MEDIUM"
	// RiskClean indicates no security violations.
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
	HasContracts bool // Whether rules.yaml exists in the skill dir
}

// ClassifyRisk returns the highest severity tier from the given violations.
// Returns RiskClean if violations is empty.
func ClassifyRisk(violations []Finding) RiskTier {
	if len(violations) == 0 {
		return RiskClean
	}

	tier := RiskClean
	for _, f := range violations {
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
			// Low and info violations do not affect the risk tier.
		}
	}
	return tier
}
