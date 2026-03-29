package guard

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/telemetry"
	"github.com/edictum-ai/edictum-go/toolcall"
)

// RunOption configures a single Run() call.
type RunOption func(*runConfig)

type runConfig struct {
	sessionID   string
	environment string
	principal   *toolcall.Principal
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
func WithRunPrincipal(p *toolcall.Principal) RunOption {
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

	env2, err := toolcall.CreateToolCall(ctx, toolcall.CreateToolCallOptions{
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

	// Start governance span. Truncate tool name in span name to prevent
	// very long names from polluting trace backend indexes.
	spanTool := env2.ToolName()
	if len(spanTool) > 64 {
		runes := []rune(spanTool)
		if len(runes) > 64 {
			runes = runes[:64]
		}
		spanTool = string(runes)
	}
	ctx, span := g.telemetry.Tracer().Start(ctx, "edictum.governance "+spanTool,
		trace.WithAttributes(telemetry.ToolSpanAttrs(
			env2.ToolName(),
			string(env2.SideEffect()),
			env2.Environment(),
			env2.RunID(),
			env2.CallIndex(),
		)...),
	)
	defer span.End()

	// Increment attempts BEFORE pre-execute checks limits.MaxAttempts.
	// This is intentional parity with Python (_runner.py:79) where
	// increment_attempts() is called before pre_execute(). With
	// max_attempts=1, the first call sees attempt_count=1 which equals
	// the limit, so it is allowed; the second call sees attempt_count=2
	// which exceeds the limit, so it is denied.
	if _, err := sess.IncrementAttempts(ctx); err != nil {
		telemetry.SetSpanError(span, fmt.Sprintf("increment attempts: %v", err))
		return nil, fmt.Errorf("increment attempts: %w", err)
	}

	pipe := pipeline.New(g)
	pre, err := pipe.PreExecute(ctx, env2, sess)
	if err != nil {
		telemetry.SetSpanError(span, fmt.Sprintf("pre-execute: %v", err))
		return nil, fmt.Errorf("pre-execute: %w", err)
	}

	// Handle approval flow regardless of guard mode. Python/TS only let
	// ordinary denies fall through in observe mode; pending_approval still
	// goes through the approval backend.
	if pre.Action == "pending_approval" {
		return g.handleApproval(ctx, env2, sess, pipe, pre, mode, policyVersion, toolCallable, args)
	}

	return g.handlePreDecision(ctx, env2, sess, pipe, pre, mode, policyVersion, toolCallable, args)
}

// handlePreDecision routes the pre-execution decision.
func (g *Guard) handlePreDecision(
	ctx context.Context,
	env2 toolcall.ToolCall,
	sess *session.Session,
	pipe *pipeline.CheckPipeline,
	pre pipeline.PreDecision,
	mode, policyVersion string,
	toolCallable func(map[string]any) (any, error),
	args map[string]any,
) (any, error) {
	realDeny := pre.Action == "block" && !pre.Observed

	if realDeny {
		action := audit.ActionCallBlocked
		if mode == "observe" {
			action = audit.ActionCallWouldBlock
		}
		g.emitPreAudit(ctx, env2, sess, action, pre, mode, policyVersion)

		if mode == "enforce" {
			telemetry.SetSpanError(trace.SpanFromContext(ctx), "rule blocked: "+pre.DecisionName)
			g.telemetry.RecordDenial(ctx, env2.ToolName())
			g.fireOnBlock(env2, pre.Reason, pre.DecisionName)
			return nil, &edictum.BlockedError{
				Reason:         pre.Reason,
				DecisionSource: pre.DecisionSource,
				DecisionName:   pre.DecisionName,
			}
		}
		// observe mode: record denial (rule fired) then fall through
		g.telemetry.RecordDenial(ctx, env2.ToolName())
		trace.SpanFromContext(ctx).SetAttributes(attribute.Bool("governance.observed_deny", true))
	} else {
		// Emit CALL_WOULD_BLOCK for per-rule observed denials
		g.emitObservedDenials(ctx, env2, pre, policyVersion)
		g.emitPreAudit(ctx, env2, sess, audit.ActionCallAllowed, pre, mode, policyVersion)
		g.telemetry.RecordAllowed(ctx, env2.ToolName())
		g.fireOnAllow(env2)
	}

	// Emit observe-mode audit events
	g.emitObserveResults(ctx, env2, pre, policyVersion)

	return g.executeAndPost(ctx, env2, sess, pipe, pre, mode, policyVersion, toolCallable, args)
}
