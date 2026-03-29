package guard

import "github.com/edictum-ai/edictum-go/toolcall"

func principalMap(p *toolcall.Principal) map[string]any {
	if p == nil {
		return nil
	}
	result := map[string]any{}
	if v := p.UserID(); v != "" {
		result["user_id"] = v
	}
	if v := p.ServiceID(); v != "" {
		result["service_id"] = v
	}
	if v := p.OrgID(); v != "" {
		result["org_id"] = v
	}
	if v := p.Role(); v != "" {
		result["role"] = v
	}
	if v := p.TicketRef(); v != "" {
		result["ticket_ref"] = v
	}
	if claims := p.Claims(); claims != nil {
		result["claims"] = claims
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
