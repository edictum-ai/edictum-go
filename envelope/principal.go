package envelope

import "github.com/edictum-ai/edictum-go/internal/deepcopy"

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

// Claims returns a deep copy of the principal's claims.
func (p Principal) Claims() map[string]any {
	return deepcopy.Map(p.claims)
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
		p.claims = deepcopy.Map(claims)
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
