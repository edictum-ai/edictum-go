package guard

import (
	"log"

	"github.com/edictum-ai/edictum-go/toolcall"
)

// factoryCfg holds options meaningful only for factory constructors
// (FromYAML, FromYAMLString, FromServer). Stored on the Guard during
// option extraction via extractFactory, never on the returned Guard.
type factoryCfg struct {
	// YAML compilation extensions
	customOperators map[string]func(any, any) bool
	customSelectors map[string]func(toolcall.ToolCall) map[string]any

	// Server connection configuration
	bundleName       string
	tags             map[string]string
	autoWatch        bool
	allowInsecure    bool
	verifySignatures bool
	signingPublicKey string
}

// suppressFactoryWarnings is an internal option prepended by factory
// constructors. It sets factoryBuild=true so factory-only options
// applied during New() don't emit spurious warnings.
func suppressFactoryWarnings() Option {
	return func(g *Guard) { g.factoryBuild = true }
}

// WithCustomOperators sets custom condition operators for YAML compilation.
// Factory-only: logs a warning when passed to New() directly.
func WithCustomOperators(ops map[string]func(any, any) bool) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.customOperators = ops
		} else if !g.factoryBuild {
			log.Printf("guard: WithCustomOperators has no effect outside FromYAML/FromYAMLString")
		}
	}
}

// WithCustomSelectors sets custom envelope selectors for YAML compilation.
// Factory-only: logs a warning when passed to New() directly.
func WithCustomSelectors(sels map[string]func(toolcall.ToolCall) map[string]any) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.customSelectors = sels
		} else if !g.factoryBuild {
			log.Printf("guard: WithCustomSelectors has no effect outside FromYAML/FromYAMLString")
		}
	}
}

// WithBundleName sets the rule bundle lineage to track on the server.
// Factory-only: logs a warning when passed to New() directly.
func WithBundleName(name string) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.bundleName = name
		} else if !g.factoryBuild {
			log.Printf("guard: WithBundleName has no effect outside FromServer")
		}
	}
}

// WithTags sets key-value metadata describing this agent instance.
// Factory-only: logs a warning when passed to New() directly.
func WithTags(tags map[string]string) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.tags = tags
		} else if !g.factoryBuild {
			log.Printf("guard: WithTags has no effect outside FromServer")
		}
	}
}

// WithAutoWatch controls whether the SSE watcher for rule hot-reload
// starts automatically. Default: true.
// Factory-only: logs a warning when passed to New() directly.
func WithAutoWatch(enabled bool) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.autoWatch = enabled
		} else if !g.factoryBuild {
			log.Printf("guard: WithAutoWatch has no effect outside FromServer")
		}
	}
}

// WithAllowInsecure permits plaintext HTTP to non-loopback hosts.
// Factory-only: logs a warning when passed to New() directly.
func WithAllowInsecure() Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.allowInsecure = true
		} else if !g.factoryBuild {
			log.Printf("guard: WithAllowInsecure has no effect outside FromServer")
		}
	}
}

// WithVerifySignatures enables Ed25519 signature verification on bundles
// fetched from the server. The publicKeyHex must be a hex-encoded Ed25519
// public key. Factory-only: logs a warning when passed to New() directly.
func WithVerifySignatures(publicKeyHex string) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.verifySignatures = true
			g.factoryCfg.signingPublicKey = publicKeyHex
		} else if !g.factoryBuild {
			log.Printf("guard: WithVerifySignatures has no effect outside FromServer; "+
				"signature verification requires a server connection (key=%q)", publicKeyHex)
		}
	}
}
