package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/edictum-ai/edictum-go/skill"
	"github.com/spf13/cobra"
)

func newSkillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skill",
		Short: "Skill security scanning",
	}
	cmd.AddCommand(newSkillScanCmd())
	return cmd
}

func newSkillScanCmd() *cobra.Command {
	var (
		jsonOutput     bool
		threshold      string
		structuralOnly bool
		verbose        bool
	)

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a skill directory or SKILL.md for security risks",
		Long:  "Scan a skill directory (or SKILL.md file) for dangerous patterns, obfuscation, and missing rules. Supports batch scanning of skill collections.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			thresh, err := parseThreshold(threshold)
			if err != nil {
				return err
			}
			return runSkillScan(cmd, args[0], jsonOutput, thresh, structuralOnly, verbose)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVar(&threshold, "threshold", "MEDIUM", "minimum risk level for non-zero exit (CRITICAL, HIGH, MEDIUM)")
	cmd.Flags().BoolVar(&structuralOnly, "structural-only", false, "only check rules.yaml presence")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show all details even for clean skills")

	return cmd
}

func runSkillScan(cmd *cobra.Command, path string, jsonOut bool, threshold skill.RiskTier, structuralOnly, verbose bool) error {
	results, batch, err := collectResults(path, structuralOnly)
	if err != nil {
		return err
	}

	if jsonOut {
		return printSkillJSON(cmd, results, threshold, batch)
	}
	return printSkillText(cmd, results, threshold, verbose, batch)
}

// collectResults scans a single skill or a directory of skills.
// Returns batch=true when scanning multiple subdirectories.
func collectResults(path string, structuralOnly bool) ([]*skill.ScanResult, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, fmt.Errorf("stat %s: %w", path, err)
	}

	// Single file: scan directly.
	if !info.IsDir() {
		r, err := scanOne(path, structuralOnly)
		if err != nil {
			return nil, false, err
		}
		return []*skill.ScanResult{r}, false, nil
	}

	// Directory with SKILL.md: single skill.
	if _, serr := os.Stat(filepath.Join(path, "SKILL.md")); serr == nil {
		r, err := scanOne(path, structuralOnly)
		if err != nil {
			return nil, false, err
		}
		return []*skill.ScanResult{r}, false, nil
	}

	// Batch: scan subdirectories that contain SKILL.md.
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, false, fmt.Errorf("reading directory %s: %w", path, err)
	}

	var results []*skill.ScanResult
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(path, e.Name())
		if _, serr := os.Stat(filepath.Join(sub, "SKILL.md")); serr != nil {
			continue
		}
		r, err := scanOne(sub, structuralOnly)
		if err != nil {
			return nil, false, err
		}
		results = append(results, r)
	}

	if len(results) == 0 {
		return nil, false, fmt.Errorf("no skills found in %s", path)
	}
	return results, true, nil
}

func scanOne(path string, structuralOnly bool) (*skill.ScanResult, error) {
	if structuralOnly {
		return skill.ScanSkillStructural(path)
	}
	return skill.ScanSkill(path)
}

// riskAtOrAbove returns true if tier >= threshold in severity ordering.
func riskAtOrAbove(tier, threshold skill.RiskTier) bool {
	return riskLevel(tier) >= riskLevel(threshold)
}

func riskLevel(t skill.RiskTier) int {
	switch t {
	case skill.RiskCritical:
		return 3
	case skill.RiskHigh:
		return 2
	case skill.RiskMedium:
		return 1
	case skill.RiskClean:
		return 0
	default:
		return 0
	}
}

func parseThreshold(s string) (skill.RiskTier, error) {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return skill.RiskCritical, nil
	case "HIGH":
		return skill.RiskHigh, nil
	case "MEDIUM":
		return skill.RiskMedium, nil
	default:
		return "", fmt.Errorf("invalid threshold %q: must be CRITICAL, HIGH, or MEDIUM", s)
	}
}

func anyAtOrAbove(results []*skill.ScanResult, threshold skill.RiskTier) bool {
	for _, r := range results {
		if riskAtOrAbove(r.RiskTier, threshold) {
			return true
		}
	}
	return false
}

func printSkillJSON(cmd *cobra.Command, results []*skill.ScanResult, _ skill.RiskTier, batch bool) error {
	w := cmd.OutOrStdout()
	if !batch && len(results) == 1 {
		return writeJSONTo(w, results[0])
	}
	type batchOutput struct {
		TotalScanned int                 `json:"total_scanned"`
		Results      []*skill.ScanResult `json:"results"`
		Stats        map[string]int      `json:"stats"`
	}
	stats := countTiers(results)
	return writeJSONTo(w, batchOutput{
		TotalScanned: len(results),
		Results:      results,
		Stats:        stats,
	})
}

func printSkillText(cmd *cobra.Command, results []*skill.ScanResult, threshold skill.RiskTier, verbose, batch bool) error {
	w := cmd.OutOrStdout()
	for _, r := range results {
		if r.RiskTier == skill.RiskClean && !verbose {
			continue
		}
		printSingleResult(w, r)
	}

	if batch {
		stats := countTiers(results)
		fmt.Fprintf(w, "\nScanned %d skills: %d CRITICAL, %d HIGH, %d MEDIUM, %d CLEAN\n",
			len(results), stats["CRITICAL"], stats["HIGH"], stats["MEDIUM"], stats["CLEAN"])
	}

	if anyAtOrAbove(results, threshold) {
		return &exitError{code: 1}
	}
	return nil
}

func printSingleResult(w io.Writer, r *skill.ScanResult) {
	switch r.RiskTier {
	case skill.RiskCritical:
		fmt.Fprintf(w, "\n\u26a0 CRITICAL: %s\n\n", r.SkillName)
	case skill.RiskHigh:
		fmt.Fprintf(w, "\n\u26a0 HIGH: %s\n\n", r.SkillName)
	case skill.RiskMedium:
		fmt.Fprintf(w, "\n\u26a0 MEDIUM: %s\n\n", r.SkillName)
	case skill.RiskClean:
		fmt.Fprintf(w, "\n\u2713 CLEAN: %s\n  No security violations detected.\n", r.SkillName)
		return
	}

	for _, f := range r.Findings {
		if f.Line > 0 {
			fmt.Fprintf(w, "  [%s] %s (line %d)\n", f.Severity, f.Message, f.Line)
		} else {
			fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Message)
		}
	}
	if !r.HasContracts {
		fmt.Fprintln(w, "  [INFO] no rules.yaml found")
	}

	if r.RiskTier == skill.RiskCritical || r.RiskTier == skill.RiskHigh {
		fmt.Fprintln(w, "\n  Decision: DO NOT INSTALL without review")
	}
}

func countTiers(results []*skill.ScanResult) map[string]int {
	stats := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "CLEAN": 0}
	for _, r := range results {
		stats[string(r.RiskTier)]++
	}
	return stats
}
