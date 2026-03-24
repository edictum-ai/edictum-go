package guard

import (
	"fmt"

	"go.opentelemetry.io/otel/trace"

	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/contract"
	"github.com/edictum-ai/edictum-go/envelope"
	"github.com/edictum-ai/edictum-go/pipeline"
	"github.com/edictum-ai/edictum-go/redaction"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/telemetry"
)

// Option configures a Guard.
type Option func(*Guard)

// WithEnvironment sets the environment name (default: "production").
func WithEnvironment(env string) Option {
	return func(g *Guard) { g.environment = env }
}

// WithMode sets the enforcement mode: "enforce" or "observe".
// Panics on invalid mode to fail-closed at construction time.
func WithMode(mode string) Option {
	if mode != "enforce" && mode != "observe" {
		panic("invalid mode " + mode + ": must be \"enforce\" or \"observe\"")
	}
	return func(g *Guard) { g.mode = mode }
}

// WithLimits sets the operation limits.
func WithLimits(limits pipeline.OperationLimits) Option {
	return func(g *Guard) { g.state.limits = limits }
}

// WithContracts adds contracts to the guard. Accepts Precondition,
// Postcondition, and SessionContract values. Each is sorted into
// enforce or observe lists based on its Mode field.
//
// Panics on unsupported types (construction-time programmer error,
// like regexp.MustCompile). This is intentional: the functional option
// signature has no error return, and silently ignoring an unknown type
// would violate the API design rule "never silently ignore".
func WithContracts(contracts ...any) Option {
	return func(g *Guard) {
		for _, c := range contracts {
			switch v := c.(type) {
			case contract.Precondition:
				if v.Mode == "observe" {
					g.state.observePreconditions = append(
						g.state.observePreconditions, v)
				} else {
					g.state.preconditions = append(
						g.state.preconditions, v)
				}
			case contract.Postcondition:
				if v.Mode == "observe" {
					g.state.observePostconditions = append(
						g.state.observePostconditions, v)
				} else {
					g.state.postconditions = append(
						g.state.postconditions, v)
				}
			case contract.SessionContract:
				if v.Mode == "observe" {
					g.state.observeSessionContracts = append(
						g.state.observeSessionContracts, v)
				} else {
					g.state.sessionContracts = append(
						g.state.sessionContracts, v)
				}
			default:
				panic(fmt.Sprintf("WithContracts: unsupported type %T", c))
			}
		}
	}
}

// WithHooks registers before/after hooks.
func WithHooks(hooks ...pipeline.HookRegistration) Option {
	return func(g *Guard) {
		for _, h := range hooks {
			if h.Phase == "before" {
				g.beforeHooks = append(g.beforeHooks, h)
			} else {
				g.afterHooks = append(g.afterHooks, h)
			}
		}
	}
}

// WithAuditSink sets external audit sinks. The local collecting sink
// is always prepended to ensure mark/since_mark functionality.
func WithAuditSink(sinks ...audit.Sink) Option {
	return func(g *Guard) {
		all := make([]audit.Sink, 0, 1+len(sinks))
		all = append(all, g.localSink)
		all = append(all, sinks...)
		g.auditSink = audit.NewCompositeSink(all...)
	}
}

// WithRedaction sets the redaction policy.
func WithRedaction(p *redaction.Policy) Option {
	return func(g *Guard) { g.redactionPolicy = p }
}

// WithBackend sets the session storage backend.
func WithBackend(b session.StorageBackend) Option {
	return func(g *Guard) { g.backend = b }
}

// WithPolicyVersion sets the policy version identifier.
func WithPolicyVersion(v string) Option {
	return func(g *Guard) { g.state.policyVersion = v }
}

// WithOnDeny sets the callback invoked when a tool call is denied.
func WithOnDeny(fn func(envelope.ToolEnvelope, string, string)) Option {
	return func(g *Guard) { g.onDeny = fn }
}

// WithOnAllow sets the callback invoked when a tool call is allowed.
func WithOnAllow(fn func(envelope.ToolEnvelope)) Option {
	return func(g *Guard) { g.onAllow = fn }
}

// WithOnPostWarn sets the callback invoked when postconditions produce warnings.
func WithOnPostWarn(fn func(envelope.ToolEnvelope, []string)) Option {
	return func(g *Guard) { g.onPostWarn = fn }
}

// WithSuccessCheck sets a custom success check function.
func WithSuccessCheck(fn func(string, any) bool) Option {
	return func(g *Guard) { g.successCheck = fn }
}

// WithPrincipal sets a static principal for all tool calls.
func WithPrincipal(p *envelope.Principal) Option {
	return func(g *Guard) { g.principal = p }
}

// WithPrincipalResolver sets a function that resolves a principal
// per tool call. Overrides WithPrincipal when set.
func WithPrincipalResolver(fn func(string, map[string]any) *envelope.Principal) Option {
	return func(g *Guard) { g.principalResolver = fn }
}

// WithApprovalBackend sets the human-in-the-loop approval backend.
func WithApprovalBackend(b approval.Backend) Option {
	return func(g *Guard) { g.approvalBackend = b }
}

// WithTools registers tools from a map of name to config.
// Config keys: "side_effect" (string), "idempotent" (bool).
func WithTools(tools map[string]map[string]any) Option {
	return func(g *Guard) {
		for name, cfg := range tools {
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
}

// WithTracerProvider sets an OpenTelemetry TracerProvider for governance spans.
// Falls back to the global TracerProvider if not set, which returns no-op
// spans when no OTel SDK is configured.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(g *Guard) {
		if g.telemetry == nil {
			g.telemetry = telemetry.New(telemetry.WithTracerProvider(tp))
		}
	}
}

// WithTelemetry sets a pre-configured GovernanceTelemetry instance.
func WithTelemetry(t *telemetry.GovernanceTelemetry) Option {
	return func(g *Guard) { g.telemetry = t }
}

// WithSandboxContracts adds sandbox contracts (preconditions matched
// against multiple tool patterns).
func WithSandboxContracts(contracts ...contract.Precondition) Option {
	return func(g *Guard) {
		for _, c := range contracts {
			if c.Mode == "observe" {
				g.state.observeSandboxContracts = append(
					g.state.observeSandboxContracts, c)
			} else {
				g.state.sandboxContracts = append(
					g.state.sandboxContracts, c)
			}
		}
	}
}
