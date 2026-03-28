package guard

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/toolcall"
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
		toolRegistry: toolcall.NewToolRegistry(),
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
		toolRegistry: toolcall.NewToolRegistry(),
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
//
// All paths are canonicalized via filepath.EvalSymlinks. When scanning
// a directory, entries whose resolved target falls outside the canonical
// root are silently skipped (symlink escape prevention).
func resolvePaths(path string) ([]string, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(canonical)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{canonical}, nil
	}

	entries, err := os.ReadDir(canonical)
	if err != nil {
		return nil, err
	}

	prefix := canonical + string(filepath.Separator)
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		full := filepath.Join(canonical, e.Name())
		resolved, evalErr := filepath.EvalSymlinks(full)
		if evalErr != nil {
			continue // broken symlink — skip
		}
		// Ensure resolved target stays within the canonical root.
		if !strings.HasPrefix(resolved, prefix) {
			continue // symlink escapes rules directory — skip
		}
		files = append(files, resolved)
	}
	sort.Strings(files)
	return files, nil
}
