package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "validate <files...>",
		Short: "Validate YAML rule bundles",
		Long:  "Validate one or more YAML rule bundles. Exits 1 if any are invalid.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(cmd, args, jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	return cmd
}

type validateFileResult struct {
	File   string         `json:"file"`
	Valid  bool           `json:"valid"`
	Error  string         `json:"error,omitempty"`
	Total  int            `json:"total"`
	Counts map[string]int `json:"counts,omitempty"`
}

type validateOutput struct {
	Files    []validateFileResult `json:"files"`
	Valid    bool                 `json:"valid"`
	Composed *composedOutput      `json:"composed,omitempty"`
}

type composedOutput struct {
	Overrides []overrideOutput `json:"overrides,omitempty"`
	Observes  []observeOutput  `json:"observes,omitempty"`
}

type overrideOutput struct {
	RuleID         string `json:"rule_id"`
	OverriddenBy   string `json:"overridden_by"`
	OriginalSource string `json:"original_source"`
}

type observeOutput struct {
	RuleID         string `json:"rule_id"`
	EnforcedSource string `json:"enforced_source"`
	ObservedSource string `json:"observed_source"`
}

func runValidate(cmd *cobra.Command, files []string, jsonOut bool) error {
	results := make([]validateFileResult, 0, len(files))
	allValid := true

	validBundles := make([]bundleFile, 0, len(files))

	for _, f := range files {
		name := filepath.Base(f)
		data, hash, err := yamlpkg.LoadBundle(f)
		if err != nil {
			results = append(results, validateFileResult{
				File: name, Valid: false, Error: err.Error(),
			})
			allValid = false
			continue
		}

		if _, compileErr := yamlpkg.Compile(data); compileErr != nil {
			results = append(results, validateFileResult{
				File: name, Valid: false, Error: compileErr.Error(),
			})
			allValid = false
			continue
		}

		counts := countContracts(data)
		total := counts["pre"] + counts["post"] + counts["session"] + counts["sandbox"]

		results = append(results, validateFileResult{
			File: name, Valid: true, Total: total, Counts: counts,
		})
		validBundles = append(validBundles, bundleFile{
			path: f, data: data, hash: hash,
		})
	}

	// Compose if 2+ valid bundles.
	var composed *composedOutput
	if len(validBundles) >= 2 {
		entries := make([]yamlpkg.BundleEntry, len(validBundles))
		for i, b := range validBundles {
			entries[i] = yamlpkg.BundleEntry{Data: b.data, Label: filepath.Base(b.path)}
		}
		result, err := yamlpkg.ComposeBundles(entries...)
		if err == nil {
			composed = buildComposedOutput(result.Report)
		}
	}

	if jsonOut {
		return printValidateJSON(cmd, results, allValid, composed)
	}
	return printValidateText(cmd, results, composed, allValid)
}

func buildComposedOutput(report yamlpkg.CompositionReport) *composedOutput {
	if len(report.Overrides) == 0 && len(report.Observes) == 0 {
		return nil
	}
	out := &composedOutput{}
	for _, o := range report.Overrides {
		out.Overrides = append(out.Overrides, overrideOutput{
			RuleID:         o.RuleID,
			OverriddenBy:   o.OverriddenBy,
			OriginalSource: o.OriginalSource,
		})
	}
	for _, o := range report.Observes {
		out.Observes = append(out.Observes, observeOutput{
			RuleID:         o.RuleID,
			EnforcedSource: o.EnforcedSource,
			ObservedSource: o.ObservedSource,
		})
	}
	return out
}

func printValidateJSON(
	cmd *cobra.Command,
	results []validateFileResult,
	allValid bool,
	composed *composedOutput,
) error {
	out := validateOutput{
		Files: results, Valid: allValid, Composed: composed,
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("json encode: %w", err)
	}
	if !allValid {
		return &exitError{code: 1}
	}
	return nil
}

func printValidateText(
	cmd *cobra.Command,
	results []validateFileResult,
	composed *composedOutput,
	allValid bool,
) error {
	w := cmd.OutOrStdout()
	for _, r := range results {
		if r.Valid {
			fmt.Fprintf(w, "\u2713 %s \u2014 %d rules (%d pre, %d post, %d session, %d sandbox)\n",
				r.File, r.Total,
				r.Counts["pre"], r.Counts["post"],
				r.Counts["session"], r.Counts["sandbox"])
		} else {
			fmt.Fprintf(w, "\u2717 %s \u2014 %s\n", r.File, r.Error)
		}
	}

	if composed != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Composition report:")
		for _, o := range composed.Overrides {
			fmt.Fprintf(w, "  override: %s (%s replaces %s)\n",
				o.RuleID, o.OverriddenBy, o.OriginalSource)
		}
		for _, o := range composed.Observes {
			fmt.Fprintf(w, "  observe: %s (enforced=%s, observed=%s)\n",
				o.RuleID, o.EnforcedSource, o.ObservedSource)
		}
	}

	if !allValid {
		return &exitError{code: 1}
	}
	return nil
}
