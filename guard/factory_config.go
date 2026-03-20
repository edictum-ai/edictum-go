package guard

import (
	"log"

	"github.com/edictum-ai/edictum-go/envelope"
)

// factoryCfg holds options meaningful only for factory constructors
// (FromYAML, FromYAMLString, FromServer). Stored on the Guard during
// option extraction via extractFactory, never on the returned Guard.
type factoryCfg struct {
	// YAML compilation extensions
	customOperators map[string]func(any, any) bool
	customSelectors map[string]func(envelope.ToolEnvelope) map[string]any

	// Server connection configuration
	bundleName       string
	tags             map[string]string
	autoWatch        bool
	allowInsecure    bool
	verifySignatures bool
	signingPublicKey string
}

// WithCustomOperators sets custom condition operators for YAML compilation.
// Factory-only: has no effect when passed to New() directly.
func WithCustomOperators(ops map[string]func(any, any) bool) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.customOperators = ops
		}
	}
}

// WithCustomSelectors sets custom envelope selectors for YAML compilation.
// Factory-only: has no effect when passed to New() directly.
func WithCustomSelectors(sels map[string]func(envelope.ToolEnvelope) map[string]any) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.customSelectors = sels
		}
	}
}

// WithBundleName sets the contract bundle lineage to track on the server.
// Factory-only: has no effect when passed to New() directly.
func WithBundleName(name string) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.bundleName = name
		}
	}
}

// WithTags sets key-value metadata describing this agent instance.
// Factory-only: has no effect when passed to New() directly.
func WithTags(tags map[string]string) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.tags = tags
		}
	}
}

// WithAutoWatch controls whether the SSE watcher for contract hot-reload
// starts automatically. Default: true.
// Factory-only: has no effect when passed to New() directly.
func WithAutoWatch(enabled bool) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.autoWatch = enabled
		}
	}
}

// WithAllowInsecure permits plaintext HTTP to non-loopback hosts.
// Factory-only: has no effect when passed to New() directly.
func WithAllowInsecure() Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.allowInsecure = true
		}
	}
}

// WithVerifySignatures enables Ed25519 signature verification on bundles
// fetched from the server. The publicKeyHex must be a hex-encoded Ed25519
// public key. Factory-only: logs a warning when passed to New() directly
// since signature verification requires a server connection.
func WithVerifySignatures(publicKeyHex string) Option {
	return func(g *Guard) {
		if g.factoryCfg != nil {
			g.factoryCfg.verifySignatures = true
			g.factoryCfg.signingPublicKey = publicKeyHex
		} else {
			log.Printf("guard: WithVerifySignatures has no effect outside FromServer; "+
				"signature verification requires a server connection (key=%q)", publicKeyHex)
		}
	}
}
