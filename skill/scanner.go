package skill

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// maxFileSize is the maximum SKILL.md file size the scanner will read (1 MB).
const maxFileSize = 1_048_576

// base64Re matches potential base64-encoded blobs of 20+ characters.
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// ScanSkill scans a skill directory or SKILL.md file for security risks.
// If path is a directory, it looks for SKILL.md inside it.
// If path is a file, it scans that file directly.
func ScanSkill(path string) (*ScanResult, error) {
	filePath, dirPath, err := resolvePaths(path)
	if err != nil {
		return nil, err
	}

	data, err := readBounded(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}

	content := string(data)
	blocks := extractCodeBlocks(content)

	blockFindings := scanCodeBlocks(blocks)
	blobFindings := scanBase64Blobs(blocks)
	findings := make([]Finding, 0, len(blockFindings)+len(blobFindings))
	findings = append(findings, blockFindings...)
	findings = append(findings, blobFindings...)

	hasContracts := checkContracts(dirPath)

	return &ScanResult{
		SkillName:    filepath.Base(dirPath),
		SkillPath:    filePath,
		RiskTier:     ClassifyRisk(findings),
		Findings:     findings,
		HasContracts: hasContracts,
	}, nil
}

// ScanSkillStructural performs structural-only analysis, checking
// whether contracts.yaml exists in the skill directory without
// scanning file content for patterns.
func ScanSkillStructural(path string) (*ScanResult, error) {
	_, dirPath, err := resolvePaths(path)
	if err != nil {
		return nil, err
	}

	hasContracts := checkContracts(dirPath)

	return &ScanResult{
		SkillName:    filepath.Base(dirPath),
		SkillPath:    path,
		RiskTier:     RiskClean,
		Findings:     nil,
		HasContracts: hasContracts,
	}, nil
}

// resolvePaths determines the SKILL.md file path and parent directory
// from the given path, which may be a file or directory.
func resolvePaths(path string) (filePath, dirPath string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("stat %s: %w", path, err)
	}

	if info.IsDir() {
		dirPath = path
		filePath = filepath.Join(path, "SKILL.md")
		if _, err := os.Stat(filePath); err != nil {
			return "", "", fmt.Errorf("no SKILL.md in %s: %w", path, err)
		}
	} else {
		filePath = path
		dirPath = filepath.Dir(path)
	}
	return filePath, dirPath, nil
}

// readBounded reads a file up to maxFileSize bytes.
func readBounded(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("file size %d exceeds %d byte limit", info.Size(), maxFileSize)
	}
	return os.ReadFile(path) //nolint:gosec // path is validated by caller via os.Stat
}

// scanCodeBlocks runs all patterns against each line of each code block.
func scanCodeBlocks(blocks []codeBlock) []Finding {
	var findings []Finding
	for _, block := range blocks {
		lines := strings.Split(block.Content, "\n")
		for lineIdx, line := range lines {
			truncated := truncateForRegex(line)
			for _, pat := range Patterns {
				if pat.Regex.MatchString(truncated) {
					findings = append(findings, Finding{
						Severity: pat.Severity,
						Category: pat.Category,
						Message:  fmt.Sprintf("matched pattern %q", pat.Name),
						Line:     block.StartLine + lineIdx + 1, // +1 for the ``` line
						Pattern:  pat.Name,
					})
				}
			}
		}
	}
	return findings
}

// scanBase64Blobs finds base64-encoded strings in code blocks, decodes
// them, checks Shannon entropy, and scans decoded content for dangerous
// patterns.
func scanBase64Blobs(blocks []codeBlock) []Finding {
	var findings []Finding
	for _, block := range blocks {
		truncated := truncateForRegex(block.Content)
		matches := base64Re.FindAllStringIndex(truncated, -1)
		for _, loc := range matches {
			raw := truncated[loc[0]:loc[1]]
			decoded, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				// Try with padding adjustment
				decoded, err = base64.RawStdEncoding.DecodeString(raw)
				if err != nil {
					continue
				}
			}
			if len(decoded) == 0 {
				continue
			}

			entropy := ShannonEntropy(decoded)
			if entropy <= highEntropyThreshold {
				continue
			}

			// Calculate the line number of the match
			lineNum := block.StartLine + 1 + strings.Count(block.Content[:loc[0]], "\n")

			// Check if decoded content contains dangerous patterns
			decodedStr := string(decoded)
			dangerousFound := false
			for _, pat := range Patterns {
				if pat.Regex.MatchString(truncateForRegex(decodedStr)) {
					findings = append(findings, Finding{
						Severity: SeverityCritical,
						Category: pat.Category,
						Message:  fmt.Sprintf("base64-decoded content matches pattern %q (entropy: %.2f)", pat.Name, entropy),
						Line:     lineNum,
						Pattern:  "base64_" + pat.Name,
					})
					dangerousFound = true
					break
				}
			}

			if !dangerousFound {
				findings = append(findings, Finding{
					Severity: SeverityMedium,
					Category: "obfuscation",
					Message:  fmt.Sprintf("high-entropy base64 blob (entropy: %.2f, length: %d)", entropy, len(decoded)),
					Line:     lineNum,
					Pattern:  "high_entropy_base64",
				})
			}
		}
	}
	return findings
}

// checkContracts returns true if contracts.yaml or contracts.yml exists
// in the given directory.
func checkContracts(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "contracts.yaml")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "contracts.yml")); err == nil {
		return true
	}
	return false
}
