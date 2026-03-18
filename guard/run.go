package guard

import (
	"context"
	"fmt"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
)

// RunOption configures a single Run() invocation.
type RunOption func(*runConfig)

type runConfig struct {
	sessionID   string
	environment string
	principal   *envelope.Principal
}

// WithSessionID overrides the guard's session ID for this call.
func WithSessionID(id string) RunOption {
	return func(c *runConfig) { c.sessionID = id }
}

// WithRunEnvironment overrides the guard's environment for this call.
func WithRunEnvironment(env string) RunOption {
	return func(c *runConfig) { c.environment = env }
}

// WithRunPrincipal overrides the principal for this call.
func WithRunPrincipal(p *envelope.Principal) RunOption {
	return func(c *runConfig) { c.principal = p }
}

// Run executes a tool call through the full governance pipeline.
// Creates session, envelope, runs pre-execute, approval, execute,
// post-execute, and audit stages.
func (g *Guard) Run(
	ctx context.Context,
	toolName string,
	args map[string]any,
	toolCallable func(map[string]any) (any, error),
	opts ...RunOption,
) (any, error) {
	g.mu.RLock()
	mode := g.mode
	env := g.environment
	sid := g.sessionID
	policyVersion := g.state.policyVersion
	backend := g.backend
	registry := g.toolRegistry
	g.mu.RUnlock()

	cfg := &runConfig{sessionID: sid, environment: env}
	for _, opt := range opts {
		opt(cfg)
	}

	sess, err := session.New(cfg.sessionID, backend)
	if err != nil {
		return nil, fmt.Errorf("session create: %w", err)
	}

	// Resolve principal
	principal := cfg.principal
	if principal == nil {
		g.mu.RLock()
		principal = g.resolvePrincipal(toolName, args)
		g.mu.RUnlock()
	}

	env2, err := envelope.CreateEnvelope(ctx, envelope.CreateEnvelopeOptions{
		ToolName:    toolName,
		Args:        args,
		RunID:       cfg.sessionID,
		Environment: cfg.environment,
		Principal:   principal,
		Registry:    registry,
	})
	if err != nil {
		return nil, fmt.Errorf("envelope create: %w", err)
	}

	// Increment attempts BEFORE pre-execute checks limits.MaxAttempts.
	// This is intentional parity with Python (_runner.py:79) where
	// increment_attempts() is called before pre_execute(). With
	// max_attempts=1, the first call sees attempt_count=1 which equals
	// the limit, so it is allowed; the second call sees attempt_count=2
	// which exceeds the limit, so it is denied.
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		return nil, fmt.Errorf("increment attempts: %w", err)
	}

	pipe := pipeline.New(g)
	pre, err := pipe.PreExecute(ctx, env2, sess)
	if err != nil {
		return nil, fmt.Errorf("pre-execute: %w", err)
	}

	// Handle approval flow — only in enforce mode.
	// In observe mode, approval contracts emit CALL_WOULD_DENY and fall
	// through to execution, consistent with how ordinary denies behave.
	if pre.Action == "pending_approval" {
		if mode == "observe" {
			g.emitPreAudit(ctx, env2, sess, audit.ActionCallWouldDeny, pre, mode, policyVersion)
			return g.executeAndPost(ctx, env2, sess, pipe, mode, policyVersion, toolCallable, args)
		}
		return g.handleApproval(ctx, env2, sess, pipe, pre, mode, policyVersion, toolCallable, args)
	}

	return g.handlePreDecision(ctx, env2, sess, pipe, pre, mode, policyVersion, toolCallable, args)
}

// handlePreDecision routes the pre-execution decision.
func (g *Guard) handlePreDecision(
	ctx context.Context,
	env2 envelope.ToolEnvelope,
	sess *session.Session,
	pipe *pipeline.GovernancePipeline,
	pre pipeline.PreDecision,
	mode, policyVersion string,
	toolCallable func(map[string]any) (any, error),
	args map[string]any,
) (any, error) {
	realDeny := pre.Action == "deny" && !pre.Observed

	if realDeny {
		action := audit.ActionCallDenied
		if mode == "observe" {
			action = audit.ActionCallWouldDeny
		}
		g.emitPreAudit(ctx, env2, sess, action, pre, mode, policyVersion)

		if mode == "enforce" {
			g.fireOnDeny(env2, pre.Reason, pre.DecisionName)
			return nil, &edictum.DeniedError{
				Reason:         pre.Reason,
				DecisionSource: pre.DecisionSource,
				DecisionName:   pre.DecisionName,
			}
		}
		// observe mode: fall through to execute
	} else {
		// Emit CALL_WOULD_DENY for per-contract observed denials
		g.emitObservedDenials(ctx, env2, pre, policyVersion)
		g.emitPreAudit(ctx, env2, sess, audit.ActionCallAllowed, pre, mode, policyVersion)
		g.fireOnAllow(env2)
	}

	// Emit observe-mode audit events
	g.emitObserveResults(ctx, env2, pre, policyVersion)

	return g.executeAndPost(ctx, env2, sess, pipe, mode, policyVersion, toolCallable, args)
}
