package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/edictum-ai/edictum-go/guard"
	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
)

// writeErrorJSONTo writes a structured error as JSON to the given writer.
func writeErrorJSONTo(w io.Writer, msg string) error {
	out := map[string]any{
		"error":   msg,
		"success": false,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// writeJSONTo writes v as indented JSON to the given writer.
func writeJSONTo(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// bundleFile holds a loaded bundle with its path and parsed data.
type bundleFile struct {
	path string
	data map[string]any
	hash yamlpkg.BundleHash
}

// loadBundles reads and parses each YAML file, returning the results.
func loadBundles(files []string) ([]bundleFile, []error) {
	results := make([]bundleFile, 0, len(files))
	var errs []error
	for _, f := range files {
		data, hash, err := yamlpkg.LoadBundle(f)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f, err))
			continue
		}
		results = append(results, bundleFile{path: f, data: data, hash: hash})
	}
	return results, errs
}

// composeAndCompile loads all files, optionally composes them, and compiles.
func composeAndCompile(files []string) (yamlpkg.CompiledRuleset, *yamlpkg.CompositionReport, error) {
	bundles, errs := loadBundles(files)
	if len(errs) > 0 {
		return yamlpkg.CompiledRuleset{}, nil, errs[0]
	}
	if len(bundles) == 0 {
		return yamlpkg.CompiledRuleset{}, nil, fmt.Errorf("no valid bundles loaded")
	}

	var bundleData map[string]any
	var report *yamlpkg.CompositionReport

	if len(bundles) == 1 {
		bundleData = bundles[0].data
	} else {
		entries := make([]yamlpkg.BundleEntry, len(bundles))
		for i, b := range bundles {
			entries[i] = yamlpkg.BundleEntry{Data: b.data, Label: b.path}
		}
		composed, err := yamlpkg.ComposeBundles(entries...)
		if err != nil {
			return yamlpkg.CompiledRuleset{}, nil, fmt.Errorf("compose: %w", err)
		}
		bundleData = composed.Bundle
		report = &composed.Report
	}

	compiled, err := yamlpkg.Compile(bundleData)
	if err != nil {
		return yamlpkg.CompiledRuleset{}, nil, fmt.Errorf("compile: %w", err)
	}
	return compiled, report, nil
}

// buildGuardFromFiles loads, composes, compiles, and constructs a Guard.
func buildGuardFromFiles(files []string, env string) (*guard.Guard, error) {
	if len(files) == 1 {
		return guard.FromYAML(files[0], guard.WithEnvironment(env))
	}

	compiled, _, err := composeAndCompile(files)
	if err != nil {
		return nil, err
	}

	opts := compiledToGuardOpts(compiled, env)
	return guard.New(opts...), nil
}

// compiledToGuardOpts converts a compiled bundle into guard options.
func compiledToGuardOpts(c yamlpkg.CompiledRuleset, env string) []guard.Option {
	opts := []guard.Option{
		guard.WithEnvironment(env),
		guard.WithLimits(c.Limits),
	}
	if c.DefaultMode != "" {
		opts = append(opts, guard.WithMode(c.DefaultMode))
	}
	if c.Tools != nil {
		opts = append(opts, guard.WithTools(c.Tools))
	}

	contractArgs := make([]any, 0,
		len(c.Preconditions)+len(c.Postconditions)+len(c.SessionRules))
	for _, p := range c.Preconditions {
		contractArgs = append(contractArgs, p)
	}
	for _, p := range c.Postconditions {
		contractArgs = append(contractArgs, p)
	}
	for _, s := range c.SessionRules {
		contractArgs = append(contractArgs, s)
	}
	if len(contractArgs) > 0 {
		opts = append(opts, guard.WithRules(contractArgs...))
	}
	if len(c.SandboxRules) > 0 {
		opts = append(opts, guard.WithSandboxRules(c.SandboxRules...))
	}
	return opts
}

// loadBundle loads a single YAML bundle file.
func loadBundle(path string) (map[string]any, yamlpkg.BundleHash, error) {
	return yamlpkg.LoadBundle(path)
}

// buildGuard is an alias for buildGuardFromFiles, used by diff/replay/test.
func buildGuard(files []string, env string) (*guard.Guard, error) {
	return buildGuardFromFiles(files, env)
}

// countContracts counts rules by type from raw bundle data.
func countContracts(data map[string]any) map[string]int {
	counts := map[string]int{"pre": 0, "post": 0, "session": 0, "sandbox": 0}
	raw, ok := data["rules"].([]any)
	if !ok {
		return counts
	}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if enabled, ok := m["enabled"].(bool); ok && !enabled {
			continue
		}
		t, _ := m["type"].(string)
		switch t {
		case "pre", "post", "session", "sandbox":
			counts[t]++
		}
	}
	return counts
}
