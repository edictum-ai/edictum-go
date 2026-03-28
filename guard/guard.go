// Package guard provides the top-level Edictum guard for rule enforcement.
package guard

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/redaction"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/telemetry"
)

// serverClient is satisfied by *server.Client. Defined here to avoid
// an import cycle between guard and server.
type serverClient interface{}

// sseCloser is satisfied by *server.SSEWatcher. Allows the guard to
// stop the SSE goroutine on Close without importing server directly.
type sseCloser interface {
	Close()
}

// compiledState is an immutable snapshot of compiled rules.
// All slices are treated as immutable after construction.
// The guard swaps the entire state atomically under a write lock
// in Reload(), ensuring concurrent evaluations never see a mix
// of old and new rules.
type compiledState struct {
	preconditions           []rule.Precondition
	postconditions          []rule.Postcondition
	sessionContracts        []rule.SessionRule
	sandboxContracts        []rule.Precondition
	observePreconditions    []rule.Precondition
	observePostconditions   []rule.Postcondition
	observeSessionRules []rule.SessionRule
	observeSandboxContracts []rule.Precondition
	limits                  pipeline.OperationLimits
	policyVersion           string
}

// Guard is the main entry point for runtime rule enforcement.
// Implements pipeline.RuleProvider and server.Reloader.
type Guard struct {
	mu                sync.RWMutex
	environment       string
	mode              string // "enforce" or "observe"
	state             *compiledState
	beforeHooks       []pipeline.HookRegistration
	afterHooks        []pipeline.HookRegistration
	toolRegistry      *toolcall.ToolRegistry
	backend           session.StorageBackend
	auditSink         audit.Sink
	localSink         *audit.CollectingSink
	redactionPolicy   *redaction.Policy
	onBlock            func(env toolcall.ToolCall, reason string, name string)
	onAllow           func(env toolcall.ToolCall)
	onPostWarn        func(env toolcall.ToolCall, warnings []string)
	successCheck      func(toolName string, result any) bool
	principal         *toolcall.Principal
	principalResolver func(toolName string, args map[string]any) *toolcall.Principal
	approvalBackend   approval.Backend
	sessionID         string

	telemetry *telemetry.GovernanceTelemetry
	telOpts   []telemetry.Option // accumulated before New() builds telemetry

	// factoryCfg is non-nil only during factory option extraction.
	// Never present on a returned Guard.
	factoryCfg *factoryCfg

	// factoryBuild suppresses factory-only option warnings during
	// internal New() calls from factory constructors.
	factoryBuild bool

	// compileOpts stores []yaml.CompileOption set by factory constructors.
	// ReloadFromYAML reuses them so custom operators/selectors survive reload.
	// Typed as any to avoid importing yaml in guard.go.
	compileOpts any

	// Server fields — set by FromServer, nil otherwise.
	serverClient serverClient       // interface to avoid import cycle
	sseCloser    sseCloser          // interface to avoid import cycle
	watchCancel  context.CancelFunc // cancels the SSE watcher goroutine
}

// New creates a new Guard with the given options.
func New(opts ...Option) *Guard {
	localSink := audit.NewCollectingSink(10000)
	g := &Guard{
		environment:  "production",
		mode:         "enforce",
		toolRegistry: toolcall.NewToolRegistry(),
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
	if g.telemetry == nil {
		g.telemetry = telemetry.New(g.telOpts...)
	}
	g.telOpts = nil
	g.redactionPolicy = ensureRedaction(g.redactionPolicy)
	classifyRules(g)
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
func (g *Guard) SetPrincipal(p *toolcall.Principal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.principal = p
}

// resolvePrincipal resolves the principal for a tool call.
// Caller must hold at least a read lock.
func (g *Guard) resolvePrincipal(toolName string, args map[string]any) *toolcall.Principal {
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

// classifyRules sorts incoming rules into enforce vs observe
// lists inside the compiled state. Called once during construction.
func classifyRules(_ *Guard) {
	// Already classified by options — nothing to reclassify.
	// This function exists as a hook for Reload() to recompile
	// from YAML. During construction, WithRules handles sorting.
}
