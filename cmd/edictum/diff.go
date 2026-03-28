package main

import (
	"fmt"
	"io"
	"reflect"
	"sort"

	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "diff <file1> <file2> [file3...]",
		Short: "Compare rule bundles",
		Long:  "Compare two or more YAML rule bundles and show differences.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 2 {
				return runDiffTwo(cmd, args[0], args[1], jsonOutput)
			}
			return runDiffCompose(cmd, args, jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	return cmd
}

type diffResult struct {
	Added     []contractRef `json:"added"`
	Removed   []contractRef `json:"removed"`
	Changed   []string      `json:"changed"`
	Unchanged []string      `json:"unchanged"`
	HasChange bool          `json:"has_changes"`
}

type contractRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func runDiffTwo(cmd *cobra.Command, path1, path2 string, jsonOut bool) error {
	w := cmd.OutOrStdout()
	data1, _, err := loadBundle(path1)
	if err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("loading %s: %s", path1, err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("loading %s: %w", path1, err)
	}
	data2, _, err := loadBundle(path2)
	if err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("loading %s: %s", path2, err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("loading %s: %w", path2, err)
	}

	byID1 := indexContracts(data1)
	byID2 := indexContracts(data2)

	result := diffResult{
		Added:     make([]contractRef, 0),
		Removed:   make([]contractRef, 0),
		Changed:   make([]string, 0),
		Unchanged: make([]string, 0),
	}

	for id, c1 := range byID1 {
		c2, exists := byID2[id]
		if !exists {
			ctype, _ := c1["type"].(string)
			result.Removed = append(result.Removed, contractRef{ID: id, Type: ctype})
			continue
		}
		if reflect.DeepEqual(c1, c2) {
			result.Unchanged = append(result.Unchanged, id)
		} else {
			result.Changed = append(result.Changed, id)
		}
	}

	for id, c2 := range byID2 {
		if _, exists := byID1[id]; !exists {
			ctype, _ := c2["type"].(string)
			result.Added = append(result.Added, contractRef{ID: id, Type: ctype})
		}
	}

	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].ID < result.Added[j].ID })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].ID < result.Removed[j].ID })
	sort.Strings(result.Changed)
	sort.Strings(result.Unchanged)

	result.HasChange = len(result.Added) > 0 || len(result.Removed) > 0 || len(result.Changed) > 0

	if jsonOut {
		return writeJSONTo(w, result)
	}
	printDiffText(w, result)

	if result.HasChange {
		return &exitError{code: 1}
	}
	return nil
}

func runDiffCompose(cmd *cobra.Command, paths []string, jsonOut bool) error {
	w := cmd.OutOrStdout()
	entries := make([]yamlpkg.BundleEntry, 0, len(paths))
	for _, p := range paths {
		data, _, err := loadBundle(p)
		if err != nil {
			if jsonOut {
				writeErrorJSONTo(w, fmt.Sprintf("loading %s: %s", p, err)) //nolint:errcheck // best-effort JSON error
				return &exitError{code: 2}
			}
			return fmt.Errorf("loading %s: %w", p, err)
		}
		entries = append(entries, yamlpkg.BundleEntry{Data: data, Label: p})
	}

	composed, err := yamlpkg.ComposeBundles(entries...)
	if err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("composing bundles: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("composing bundles: %w", err)
	}

	report := composed.Report
	hasChanges := len(report.Overrides) > 0 || len(report.Observes) > 0

	if jsonOut {
		if err := writeJSONTo(w, report); err != nil {
			return err
		}
	} else {
		printComposeText(w, report)
	}

	if hasChanges {
		return &exitError{code: 1}
	}
	return nil
}

func printDiffText(w io.Writer, r diffResult) {
	for _, c := range r.Added {
		fmt.Fprintf(w, "+ %s (type: %s)\n", c.ID, c.Type)
	}
	for _, c := range r.Removed {
		fmt.Fprintf(w, "- %s (type: %s)\n", c.ID, c.Type)
	}
	for _, id := range r.Changed {
		fmt.Fprintf(w, "~ %s\n", id)
	}
	if len(r.Unchanged) > 0 {
		fmt.Fprintf(w, "= %d rules unchanged\n", len(r.Unchanged))
	}
	fmt.Fprintf(w, "\nSummary: %d added, %d removed, %d changed, %d unchanged\n",
		len(r.Added), len(r.Removed), len(r.Changed), len(r.Unchanged))
}

func printComposeText(w io.Writer, r yamlpkg.CompositionReport) {
	if len(r.Overrides) > 0 {
		fmt.Fprintln(w, "Overrides:")
		for _, o := range r.Overrides {
			fmt.Fprintf(w, "  %s: %s overrides %s\n",
				o.ContractID, o.OverriddenBy, o.OriginalSource)
		}
	}
	if len(r.Observes) > 0 {
		fmt.Fprintln(w, "Observe rules:")
		for _, o := range r.Observes {
			fmt.Fprintf(w, "  %s: enforced=%s, observed=%s\n",
				o.ContractID, o.EnforcedSource, o.ObservedSource)
		}
	}
	if len(r.Overrides) == 0 && len(r.Observes) == 0 {
		fmt.Fprintln(w, "No composition changes.")
	}
}

// indexContracts builds a map of rule ID to rule data.
func indexContracts(data map[string]any) map[string]map[string]any {
	idx := map[string]map[string]any{}
	rules, _ := data["rules"].([]any)
	for _, raw := range rules {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id != "" {
			idx[id] = m
		}
	}
	return idx
}
