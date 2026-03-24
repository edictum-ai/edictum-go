package yaml

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/sandbox"
)

// compileSandbox creates a Precondition for sandbox contracts with the
// sandbox evaluation logic baked into the Check closure.
//
// Sandbox contracts use within/not_within/allows/not_allows — not when/then —
// so they cannot go through compilePre. The YAML fields are parsed into a
// sandbox.Config and the Check function calls sandbox.Check directly.
func compileSandbox(raw map[string]any, mode string) (contract.Precondition, error) {
	cid, _ := raw["id"].(string)
	tool := "*"
	if t, ok := raw["tool"].(string); ok {
		tool = t
	}
	isObserve, _ := raw["_observe"].(bool)

	cfg, err := parseSandboxConfig(raw)
	if err != nil {
		return contract.Precondition{}, fmt.Errorf("contract %q: %w", cid, err)
	}

	pre := contract.Precondition{
		Name:   cid,
		Tool:   tool,
		Mode:   mode,
		Source: "yaml_sandbox",
		Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
			verdict, err := sandbox.Check(env, cfg)
			if err != nil || verdict.Passed() {
				return verdict, err
			}
			template := cfg.Message
			if template == "" {
				template = verdict.Message()
			}
			return contract.Fail(expandMessage(template, env, "", nil, false)), nil
		},
	}
	if isObserve {
		pre.Mode = "observe"
	}
	return pre, nil
}

// parseSandboxConfig extracts sandbox boundaries from a raw YAML contract map.
// Path prefixes (within/not_within) are resolved via filepath.EvalSymlinks to
// match the resolution performed by sandbox.ExtractPaths on incoming tool calls.
func parseSandboxConfig(raw map[string]any) (sandbox.Config, error) {
	within, err := resolvePaths(toStringSlice(raw["within"]))
	if err != nil {
		return sandbox.Config{}, fmt.Errorf("within: %w", err)
	}
	notWithin, err := resolvePaths(toStringSlice(raw["not_within"]))
	if err != nil {
		return sandbox.Config{}, fmt.Errorf("not_within: %w", err)
	}

	cfg := sandbox.Config{
		Within:    within,
		NotWithin: notWithin,
	}
	if msg, ok := raw["message"].(string); ok {
		cfg.Message = msg
	}
	if allows, ok := raw["allows"].(map[string]any); ok {
		cfg.AllowedCommands = toStringSlice(allows["commands"])
		cfg.AllowedDomains = toStringSlice(allows["domains"])
	}
	if notAllows, ok := raw["not_allows"].(map[string]any); ok {
		cfg.BlockedDomains = toStringSlice(notAllows["domains"])
	}
	return cfg, nil
}

// resolvePaths resolves each path via filepath.EvalSymlinks. Returns an
// error if any path cannot be resolved — a typo or non-existent boundary
// path would silently produce a broken sandbox contract otherwise.
func resolvePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return paths, nil
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve boundary path %q: %w", p, err)
		}
		out[i] = resolved
	}
	return out, nil
}

// toStringSlice converts an []any of strings to []string. Returns nil if
// v is nil or not a slice. Non-string items are silently dropped — callers
// in the production path are protected by validateSandboxContracts which
// rejects non-string entries before compilation.
func toStringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
