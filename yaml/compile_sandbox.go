package yaml

import (
	"context"

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
func compileSandbox(raw map[string]any, mode string) contract.Precondition {
	cid, _ := raw["id"].(string)
	tool := "*"
	if t, ok := raw["tool"].(string); ok {
		tool = t
	}
	isObserve, _ := raw["_observe"].(bool)

	cfg := parseSandboxConfig(raw)

	pre := contract.Precondition{
		Name:   cid,
		Tool:   tool,
		Mode:   mode,
		Source: "yaml_sandbox",
		Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
			return sandbox.Check(env, cfg)
		},
	}
	if isObserve {
		pre.Mode = "observe"
	}
	return pre
}

// parseSandboxConfig extracts sandbox boundaries from a raw YAML contract map.
func parseSandboxConfig(raw map[string]any) sandbox.Config {
	cfg := sandbox.Config{
		Within:    toStringSlice(raw["within"]),
		NotWithin: toStringSlice(raw["not_within"]),
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
	return cfg
}

// toStringSlice converts an []any of strings to []string. Returns nil if
// v is nil or not a slice.
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
