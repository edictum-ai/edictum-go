package yaml

import (
	"context"

	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
)

// compileSandbox creates a stub Precondition for sandbox contracts.
// Sandbox contracts use within/not_within/allows/not_allows — not when/then —
// so they cannot go through compilePre. The actual sandbox evaluation is wired
// by the guard through the sandbox package at runtime.
func compileSandbox(raw map[string]any, mode string) contract.Precondition {
	cid, _ := raw["id"].(string)
	// Sandbox contracts use "tools" (list) not "tool" (single).
	tool := "*"
	if t, ok := raw["tool"].(string); ok {
		tool = t
	}
	isObserve, _ := raw["_shadow"].(bool)

	pre := contract.Precondition{
		Name:   cid,
		Tool:   tool,
		Mode:   mode,
		Source: "yaml_sandbox",
		// Stub: actual sandbox checks are wired by guard.
		Check: func(_ context.Context, _ envelope.ToolEnvelope) (contract.Verdict, error) {
			return contract.Pass(), nil
		},
	}
	if isObserve {
		pre.Mode = "observe"
	}
	return pre
}
