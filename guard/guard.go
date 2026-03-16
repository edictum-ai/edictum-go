// Package guard provides the top-level Edictum guard for contract enforcement.
package guard

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/redaction"
	"github.com/edictum-ai/edictum-go/session"
)

// compiledState is an immutable snapshot of compiled contracts.
// All slices are treated as immutable after construction.
// The guard swaps the entire state atomically under a write lock
// in Reload(), ensuring concurrent evaluations never see a mix
// of old and new contracts.
type compiledState struct {
	preconditions           []contract.Precondition
	postconditions          []contract.Postcondition
	sessionContracts        []contract.SessionContract
	sandboxContracts        []contract.Precondition
	observePreconditions    []contract.Precondition
	observePostconditions   []contract.Postcondition
	observeSessionContracts []contract.SessionContract
	observeSandboxContracts []contract.Precondition
	limits                  pipeline.OperationLimits
	policyVersion           string
}

// Guard is the main entry point for runtime contract enforcement.
// Implements pipeline.ContractProvider.
type Guard struct {
	mu                sync.RWMutex
	environment       string
	mode              string // "enforce" or "observe"
	state             *compiledState
	beforeHooks       []pipeline.HookRegistration
	afterHooks        []pipeline.HookRegistration
	toolRegistry      *envelope.ToolRegistry
	backend           session.StorageBackend
	auditSink         audit.Sink
	localSink         *audit.CollectingSink
	redactionPolicy   *redaction.Policy
	onDeny            func(env envelope.ToolEnvelope, reason string, name string)
	onAllow           func(env envelope.ToolEnvelope)
	onPostWarn        func(env envelope.ToolEnvelope, warnings []string)
	successCheck      func(toolName string, result any) bool
	principal         *envelope.Principal
	principalResolver func(toolName string, args map[string]any) *envelope.Principal
	approvalBackend   approval.Backend
	sessionID         string
}

// New creates a new Guard with the given options.
func New(opts ...Option) *Guard {
	localSink := audit.NewCollectingSink(10000)
	g := &Guard{
		environment:  "production",
		mode:         "enforce",
		toolRegistry: envelope.NewToolRegistry(),
		backend:      session.NewMemoryBackend(),
		localSink:    localSink,
		auditSink:    localSink,
		sessionID:    generateUUID(),
		state: &compiledState{
			limits: pipeline.DefaultLimits(),
		},
	}
	for _, opt := range opts {
		opt(g)
	}
	g.redactionPolicy = ensureRedaction(g.redactionPolicy)
	classifyContracts(g)
	return g
}

// LocalSink returns the local in-memory audit event collector.
func (g *Guard) LocalSink() *audit.CollectingSink {
	return g.localSink
}

// Limits returns the current operation limits.
func (g *Guard) Limits() pipeline.OperationLimits {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.state.limits
}

// PolicyVersion returns the active policy version hash.
func (g *Guard) PolicyVersion() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.state.policyVersion
}

// Mode returns the current enforcement mode.
func (g *Guard) Mode() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode
}

// SetPrincipal updates the principal used for subsequent tool calls.
func (g *Guard) SetPrincipal(p *envelope.Principal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.principal = p
}

// resolvePrincipal resolves the principal for a tool call.
// Caller must hold at least a read lock.
func (g *Guard) resolvePrincipal(toolName string, args map[string]any) *envelope.Principal {
	if g.principalResolver != nil {
		return g.principalResolver(toolName, args)
	}
	return g.principal
}

func ensureRedaction(p *redaction.Policy) *redaction.Policy {
	if p != nil {
		return p
	}
	return redaction.NewPolicy()
}

// generateUUID produces a v4 UUID using crypto/rand.
func generateUUID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// classifyContracts sorts incoming contracts into enforce vs observe
// lists inside the compiled state. Called once during construction.
func classifyContracts(_ *Guard) {
	// Already classified by options — nothing to reclassify.
	// This function exists as a hook for Reload() to recompile
	// from YAML. During construction, WithContracts handles sorting.
}
