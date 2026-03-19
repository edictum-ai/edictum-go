package guard

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
)

// extractFactory applies options to a temporary Guard to capture
// factory-specific config. The temporary Guard is discarded.
func extractFactory(opts []Option) *factoryCfg {
	fc := &factoryCfg{autoWatch: true}
	localSink := audit.NewCollectingSink(1)
	tmp := &Guard{
		factoryCfg:   fc,
		environment:  "production",
		mode:         "enforce",
		toolRegistry: envelope.NewToolRegistry(),
		backend:      session.NewMemoryBackend(),
		localSink:    localSink,
		auditSink:    localSink,
		state:        &compiledState{limits: pipeline.DefaultLimits()},
	}
	for _, opt := range opts {
		opt(tmp)
	}
	return fc
}

// extractFactoryAndEnv is like extractFactory but also returns the
// user-specified environment (needed by FromServer for client config).
func extractFactoryAndEnv(opts []Option) (*factoryCfg, string) {
	fc := &factoryCfg{autoWatch: true}
	localSink := audit.NewCollectingSink(1)
	tmp := &Guard{
		factoryCfg:   fc,
		environment:  "production",
		mode:         "enforce",
		toolRegistry: envelope.NewToolRegistry(),
		backend:      session.NewMemoryBackend(),
		localSink:    localSink,
		auditSink:    localSink,
		state:        &compiledState{limits: pipeline.DefaultLimits()},
	}
	for _, opt := range opts {
		opt(tmp)
	}
	return fc, tmp.environment
}

// buildCompileOpts converts factory config into yaml.CompileOption values.
func buildCompileOpts(fc *factoryCfg) []yamlpkg.CompileOption {
	var compOpts []yamlpkg.CompileOption
	if fc.customOperators != nil {
		compOpts = append(compOpts, yamlpkg.WithCompileOperators(fc.customOperators))
	}
	if fc.customSelectors != nil {
		compOpts = append(compOpts, yamlpkg.WithCompileSelectors(fc.customSelectors))
	}
	return compOpts
}

// resolvePaths resolves a path to a list of YAML file paths.
// If path is a file, returns [path]. If path is a directory,
// returns all .yaml/.yml files sorted alphabetically.
func resolvePaths(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{path}, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(path, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}
