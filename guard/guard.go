// Package guard provides the top-level Edictum guard for contract enforcement.
package guard

// Edictum is the main entry point for runtime contract enforcement.
type Edictum struct {
	// Implementation will be filled during Phase 1
}

// Option configures an Edictum guard.
type Option func(*Edictum)

// New creates a new Edictum guard with the given options.
func New(opts ...Option) *Edictum {
	g := &Edictum{}
	for _, opt := range opts {
		opt(g)
	}
	return g
}
