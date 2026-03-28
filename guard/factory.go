package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
)

// FromYAML loads YAML rule bundles from a path and returns a configured Guard.
// If path is a directory, all .yaml/.yml files are loaded and composed
// (sorted alphabetically for deterministic ordering). If path is a single
// file, that file is loaded directly.
//
// Standard Guard options (WithMode, WithEnvironment, etc.) are applied after
// YAML-derived settings, so user options override YAML defaults.
func FromYAML(path string, opts ...Option) (*Guard, error) {
	g, _, err := fromYAMLInternal(path, opts)
	return g, err
}

// FromYAMLWithReport is like FromYAML but also returns a CompositionReport
// describing which rules were overridden during multi-file composition.
func FromYAMLWithReport(path string, opts ...Option) (*Guard, *yamlpkg.CompositionReport, error) {
	return fromYAMLInternal(path, opts)
}

// FromYAMLString loads a YAML rule bundle from a string and returns a
// configured Guard. Follows the json.Unmarshal / json.NewDecoder convention.
func FromYAMLString(content string, opts ...Option) (*Guard, error) {
	fc := extractFactory(opts)

	data, hash, err := yamlpkg.LoadBundleString(content)
	if err != nil {
		return nil, fmt.Errorf("FromYAMLString: %w", err)
	}

	compOpts := buildCompileOpts(fc)
	compiled, err := yamlpkg.Compile(data, compOpts...)
	if err != nil {
		return nil, fmt.Errorf("FromYAMLString: %w", err)
	}

	g := buildGuardFromCompiled(compiled, hash.String(), compOpts, opts)
	return g, nil
}

func fromYAMLInternal(path string, opts []Option) (*Guard, *yamlpkg.CompositionReport, error) {
	fc := extractFactory(opts)

	paths, err := resolvePaths(path)
	if err != nil {
		return nil, nil, fmt.Errorf("FromYAML: %w", err)
	}
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("FromYAML: no .yaml or .yml files found in %q", path)
	}

	type loaded struct {
		data map[string]any
		hash yamlpkg.BundleHash
		path string
	}
	bundles := make([]loaded, 0, len(paths))
	for _, p := range paths {
		data, hash, loadErr := yamlpkg.LoadBundle(p)
		if loadErr != nil {
			return nil, nil, fmt.Errorf("FromYAML: %w", loadErr)
		}
		bundles = append(bundles, loaded{data: data, hash: hash, path: p})
	}

	var bundleData map[string]any
	var policyVersion string
	var report yamlpkg.CompositionReport

	if len(bundles) == 1 {
		bundleData = bundles[0].data
		policyVersion = bundles[0].hash.String()
	} else {
		entries := make([]yamlpkg.BundleEntry, len(bundles))
		for i, b := range bundles {
			entries[i] = yamlpkg.BundleEntry{Data: b.data, Label: b.path}
		}
		composed, compErr := yamlpkg.ComposeBundles(entries...)
		if compErr != nil {
			return nil, nil, fmt.Errorf("FromYAML: %w", compErr)
		}
		bundleData = composed.Bundle
		report = composed.Report

		hashParts := make([]string, len(bundles))
		for i, b := range bundles {
			hashParts[i] = b.hash.String()
		}
		compositeHash := sha256.Sum256([]byte(strings.Join(hashParts, ":")))
		policyVersion = hex.EncodeToString(compositeHash[:])
	}

	compOpts := buildCompileOpts(fc)
	compiled, err := yamlpkg.Compile(bundleData, compOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("FromYAML: %w", err)
	}

	g := buildGuardFromCompiled(compiled, policyVersion, compOpts, opts)
	return g, &report, nil
}

// buildGuardFromCompiled creates a Guard from compiled YAML rules.
// Factory-derived options are applied first, then user options override.
// suppressFactoryWarnings prevents spurious log output from factory-only
// options that are passed through to New().
func buildGuardFromCompiled(compiled yamlpkg.CompiledRuleset, policyVersion string, compOpts []yamlpkg.CompileOption, userOpts []Option) *Guard {
	factoryDefaults := compiledOpts(compiled, policyVersion)

	allOpts := make([]Option, 0, 1+len(factoryDefaults)+len(userOpts))
	allOpts = append(allOpts, suppressFactoryWarnings())
	allOpts = append(allOpts, factoryDefaults...)
	allOpts = append(allOpts, userOpts...)

	g := New(allOpts...)
	g.compileOpts = compOpts
	return g
}
