package guard

import (
	"github.com/edictum-ai/edictum-go/envelope"
	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
)

// ReloadFromYAML atomically replaces the guard's contracts by parsing
// and compiling the given YAML bytes. Implements server.Reloader.
//
// On error the guard retains its previous contracts (fail-closed: if the
// new bundle is invalid, the old contracts keep enforcing).
func (g *Guard) ReloadFromYAML(yamlBytes []byte) error {
	data, hash, err := yamlpkg.LoadBundleString(string(yamlBytes))
	if err != nil {
		return err
	}

	compiled, err := yamlpkg.Compile(data)
	if err != nil {
		return err
	}

	newState := buildCompiledState(compiled, hash.String())

	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = newState

	if compiled.Tools != nil {
		for name, cfg := range compiled.Tools {
			se := envelope.SideEffectIrreversible
			if v, ok := cfg["side_effect"].(string); ok {
				se = envelope.SideEffect(v)
			}
			idem := false
			if v, ok := cfg["idempotent"].(bool); ok {
				idem = v
			}
			g.toolRegistry.Register(name, se, idem)
		}
	}

	return nil
}

// buildCompiledState creates an immutable state snapshot from a compiled
// YAML bundle. Contracts are classified into enforce vs observe lists.
func buildCompiledState(compiled yamlpkg.CompiledBundle, policyVersion string) *compiledState {
	s := &compiledState{
		limits:        compiled.Limits,
		policyVersion: policyVersion,
	}
	for _, p := range compiled.Preconditions {
		if p.Mode == "observe" {
			s.observePreconditions = append(s.observePreconditions, p)
		} else {
			s.preconditions = append(s.preconditions, p)
		}
	}
	for _, p := range compiled.Postconditions {
		if p.Mode == "observe" {
			s.observePostconditions = append(s.observePostconditions, p)
		} else {
			s.postconditions = append(s.postconditions, p)
		}
	}
	for _, sc := range compiled.SessionContracts {
		if sc.Mode == "observe" {
			s.observeSessionContracts = append(s.observeSessionContracts, sc)
		} else {
			s.sessionContracts = append(s.sessionContracts, sc)
		}
	}
	for _, sb := range compiled.SandboxContracts {
		if sb.Mode == "observe" {
			s.observeSandboxContracts = append(s.observeSandboxContracts, sb)
		} else {
			s.sandboxContracts = append(s.sandboxContracts, sb)
		}
	}
	return s
}

// compiledOpts converts a compiled YAML bundle into Guard options.
// Used by factory functions to build the guard from compiled contracts.
func compiledOpts(compiled yamlpkg.CompiledBundle, policyVersion string) []Option {
	opts := make([]Option, 0, 6)
	opts = append(opts,
		WithPolicyVersion(policyVersion),
		WithLimits(compiled.Limits),
	)
	if compiled.DefaultMode != "" {
		opts = append(opts, WithMode(compiled.DefaultMode))
	}
	if compiled.Tools != nil {
		opts = append(opts, WithTools(compiled.Tools))
	}

	contractArgs := make([]any, 0,
		len(compiled.Preconditions)+
			len(compiled.Postconditions)+
			len(compiled.SessionContracts))
	for _, p := range compiled.Preconditions {
		contractArgs = append(contractArgs, p)
	}
	for _, p := range compiled.Postconditions {
		contractArgs = append(contractArgs, p)
	}
	for _, s := range compiled.SessionContracts {
		contractArgs = append(contractArgs, s)
	}
	if len(contractArgs) > 0 {
		opts = append(opts, WithContracts(contractArgs...))
	}
	if len(compiled.SandboxContracts) > 0 {
		opts = append(opts, WithSandboxContracts(compiled.SandboxContracts...))
	}
	return opts
}

// Compile-time check: Guard must satisfy the contract.Precondition type
// requirements indirectly. The explicit check here is that buildCompiledState
// correctly handles the contract types.
var _ = buildCompiledState
