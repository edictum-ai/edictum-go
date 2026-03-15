// Package envelope defines the ToolEnvelope type and tool classification.
package envelope

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

// SideEffect classifies the impact of a tool call.
type SideEffect string

// SideEffect classification values.
const (
	SideEffectPure         SideEffect = "pure"
	SideEffectRead         SideEffect = "read"
	SideEffectWrite        SideEffect = "write"
	SideEffectIrreversible SideEffect = "irreversible"
)

// Principal identifies who is making the tool call.
type Principal struct {
	userID    string
	serviceID string
	orgID     string
	role      string
	ticketRef string
	claims    map[string]any
}

// UserID returns the principal's user ID.
func (p Principal) UserID() string { return p.userID }

// ServiceID returns the principal's service ID.
func (p Principal) ServiceID() string { return p.serviceID }

// OrgID returns the principal's organization ID.
func (p Principal) OrgID() string { return p.orgID }

// Role returns the principal's role.
func (p Principal) Role() string { return p.role }

// TicketRef returns the principal's ticket reference.
func (p Principal) TicketRef() string { return p.ticketRef }

// Claims returns a copy of the principal's claims.
func (p Principal) Claims() map[string]any {
	if p.claims == nil {
		return nil
	}
	cp := make(map[string]any, len(p.claims))
	for k, v := range p.claims {
		cp[k] = v
	}
	return cp
}

// PrincipalOption configures a Principal.
type PrincipalOption func(*Principal)

// WithUserID sets the principal's user ID.
func WithUserID(id string) PrincipalOption {
	return func(p *Principal) { p.userID = id }
}

// WithServiceID sets the principal's service ID.
func WithServiceID(id string) PrincipalOption {
	return func(p *Principal) { p.serviceID = id }
}

// WithOrgID sets the principal's organization ID.
func WithOrgID(id string) PrincipalOption {
	return func(p *Principal) { p.orgID = id }
}

// WithRole sets the principal's role.
func WithRole(role string) PrincipalOption {
	return func(p *Principal) { p.role = role }
}

// WithTicketRef sets the principal's ticket reference.
func WithTicketRef(ref string) PrincipalOption {
	return func(p *Principal) { p.ticketRef = ref }
}

// WithClaims sets the principal's claims (deep-copied).
func WithClaims(claims map[string]any) PrincipalOption {
	return func(p *Principal) {
		p.claims = make(map[string]any, len(claims))
		for k, v := range claims {
			p.claims[k] = v
		}
	}
}

// NewPrincipal creates a new Principal with the given options.
func NewPrincipal(opts ...PrincipalOption) Principal {
	var p Principal
	for _, opt := range opts {
		opt(&p)
	}
	return p
}

// ToolEnvelope is an immutable snapshot of a tool call.
// Fields are unexported — use getter methods.
type ToolEnvelope struct {
	toolName    string
	args        map[string]any
	callID      string
	runID       string
	callIndex   int
	parentCall  string
	sideEffect  SideEffect
	idempotent  bool
	environment string
	timestamp   string
	caller      string
	toolUseID   string
	principal   *Principal
	bashCommand string
	filePath    string
	metadata    map[string]any
}

// ToolName returns the tool name.
func (e ToolEnvelope) ToolName() string { return e.toolName }

// Args returns a copy of the tool arguments.
func (e ToolEnvelope) Args() map[string]any {
	if e.args == nil {
		return nil
	}
	cp := make(map[string]any, len(e.args))
	for k, v := range e.args {
		cp[k] = v
	}
	return cp
}

// CallID returns the call ID.
func (e ToolEnvelope) CallID() string { return e.callID }

// RunID returns the run ID.
func (e ToolEnvelope) RunID() string { return e.runID }

// CallIndex returns the call index.
func (e ToolEnvelope) CallIndex() int { return e.callIndex }

// ParentCallID returns the parent call ID.
func (e ToolEnvelope) ParentCallID() string { return e.parentCall }

// SideEffect returns the classified side effect.
func (e ToolEnvelope) SideEffect() SideEffect { return e.sideEffect }

// Idempotent returns whether the tool call is idempotent.
func (e ToolEnvelope) Idempotent() bool { return e.idempotent }

// Environment returns the environment name.
func (e ToolEnvelope) Environment() string { return e.environment }

// Timestamp returns the timestamp.
func (e ToolEnvelope) Timestamp() string { return e.timestamp }

// Caller returns the caller identifier.
func (e ToolEnvelope) Caller() string { return e.caller }

// ToolUseID returns the tool use ID.
func (e ToolEnvelope) ToolUseID() string { return e.toolUseID }

// Principal returns the principal (nil if not set).
func (e ToolEnvelope) Principal() *Principal { return e.principal }

// BashCommand returns the extracted bash command.
func (e ToolEnvelope) BashCommand() string { return e.bashCommand }

// FilePath returns the extracted file path.
func (e ToolEnvelope) FilePath() string { return e.filePath }

// Metadata returns a copy of the metadata.
func (e ToolEnvelope) Metadata() map[string]any {
	if e.metadata == nil {
		return nil
	}
	cp := make(map[string]any, len(e.metadata))
	for k, v := range e.metadata {
		cp[k] = v
	}
	return cp
}

// ValidateToolName validates a tool name, rejecting empty, control chars, and path separators.
func ValidateToolName(name string) error {
	if name == "" {
		return fmt.Errorf("tool name must not be empty")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("tool name must not contain control characters")
		}
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("tool name must not contain path separators")
	}
	return nil
}

// CreateEnvelopeOptions configures envelope creation.
type CreateEnvelopeOptions struct {
	ToolName    string
	Args        map[string]any
	CallID      string
	RunID       string
	CallIndex   int
	ParentCall  string
	Environment string
	Timestamp   string
	Caller      string
	ToolUseID   string
	Principal   *Principal
	Metadata    map[string]any
	Registry    *ToolRegistry
}

// CreateEnvelope creates a new frozen ToolEnvelope.
func CreateEnvelope(_ context.Context, opts CreateEnvelopeOptions) (ToolEnvelope, error) {
	if err := ValidateToolName(opts.ToolName); err != nil {
		return ToolEnvelope{}, err
	}

	// Deep copy args
	var args map[string]any
	if opts.Args != nil {
		args = make(map[string]any, len(opts.Args))
		for k, v := range opts.Args {
			args[k] = v
		}
	}

	// Classify side effect
	sideEffect := SideEffectIrreversible
	idempotent := false
	if opts.Registry != nil {
		se, idem := opts.Registry.Classify(opts.ToolName)
		sideEffect = se
		idempotent = idem
	}

	// Extract convenience fields
	bashCmd := extractBashCommand(args)
	filePath := extractFilePath(args)

	// Bash classifier overrides registry
	if bashCmd != "" {
		bashSE := ClassifyBash(bashCmd)
		if bashSE != sideEffect {
			sideEffect = bashSE
		}
	}

	return ToolEnvelope{
		toolName:    opts.ToolName,
		args:        args,
		callID:      opts.CallID,
		runID:       opts.RunID,
		callIndex:   opts.CallIndex,
		parentCall:  opts.ParentCall,
		sideEffect:  sideEffect,
		idempotent:  idempotent,
		environment: opts.Environment,
		timestamp:   opts.Timestamp,
		caller:      opts.Caller,
		toolUseID:   opts.ToolUseID,
		principal:   opts.Principal,
		bashCommand: bashCmd,
		filePath:    filePath,
		metadata:    opts.Metadata,
	}, nil
}

func extractBashCommand(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"bash_command", "bashCommand", "command"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func extractFilePath(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"file_path", "filePath", "path"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}
