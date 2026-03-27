package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"

	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "diff <file1> <file2> [file3...]",
		Short: "Compare contract bundles",
		Long:  "Compare two or more YAML contract bundles and show differences.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 2 {
				return runDiffTwo(args[0], args[1], jsonOutput)
			}
			return runDiffCompose(args, jsonOutput)
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

func runDiffTwo(path1, path2 string, jsonOut bool) error {
	data1, _, err := loadBundle(path1)
	if err != nil {
		if jsonOut {
			writeErrorJSON(fmt.Sprintf("loading %s: %s", path1, err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("loading %s: %w", path1, err)
	}
	data2, _, err := loadBundle(path2)
	if err != nil {
		if jsonOut {
			writeErrorJSON(fmt.Sprintf("loading %s: %s", path2, err)) //nolint:errcheck // best-effort JSON error
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
		return writeJSON(result)
	}
	printDiffText(result)

	if result.HasChange {
		return &exitError{code: 1}
	}
	return nil
}

func runDiffCompose(paths []string, jsonOut bool) error {
	entries := make([]yamlpkg.BundleEntry, 0, len(paths))
	for _, p := range paths {
		data, _, err := loadBundle(p)
		if err != nil {
			if jsonOut {
				writeErrorJSON(fmt.Sprintf("loading %s: %s", p, err)) //nolint:errcheck // best-effort JSON error
				return &exitError{code: 2}
			}
			return fmt.Errorf("loading %s: %w", p, err)
		}
		entries = append(entries, yamlpkg.BundleEntry{Data: data, Label: p})
	}

	composed, err := yamlpkg.ComposeBundles(entries...)
	if err != nil {
		if jsonOut {
			writeErrorJSON(fmt.Sprintf("composing bundles: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("composing bundles: %w", err)
	}

	report := composed.Report
	hasChanges := len(report.Overrides) > 0 || len(report.Observes) > 0

	if jsonOut {
		if err := writeJSON(report); err != nil {
			return err
		}
	} else {
		printComposeText(report)
	}

	if hasChanges {
		return &exitError{code: 1}
	}
	return nil
}

func printDiffText(r diffResult) {
	for _, c := range r.Added {
		fmt.Printf("+ %s (type: %s)\n", c.ID, c.Type)
	}
	for _, c := range r.Removed {
		fmt.Printf("- %s (type: %s)\n", c.ID, c.Type)
	}
	for _, id := range r.Changed {
		fmt.Printf("~ %s\n", id)
	}
	if len(r.Unchanged) > 0 {
		fmt.Printf("= %d contracts unchanged\n", len(r.Unchanged))
	}
	fmt.Printf("\nSummary: %d added, %d removed, %d changed, %d unchanged\n",
		len(r.Added), len(r.Removed), len(r.Changed), len(r.Unchanged))
}

func printComposeText(r yamlpkg.CompositionReport) {
	if len(r.Overrides) > 0 {
		fmt.Println("Overrides:")
		for _, o := range r.Overrides {
			fmt.Printf("  %s: %s overrides %s\n",
				o.ContractID, o.OverriddenBy, o.OriginalSource)
		}
	}
	if len(r.Observes) > 0 {
		fmt.Println("Observe contracts:")
		for _, o := range r.Observes {
			fmt.Printf("  %s: enforced=%s, observed=%s\n",
				o.ContractID, o.EnforcedSource, o.ObservedSource)
		}
	}
	if len(r.Overrides) == 0 && len(r.Observes) == 0 {
		fmt.Println("No composition changes.")
	}
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// indexContracts builds a map of contract ID to contract data.
func indexContracts(data map[string]any) map[string]map[string]any {
	idx := map[string]map[string]any{}
	contracts, _ := data["contracts"].([]any)
	for _, raw := range contracts {
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
