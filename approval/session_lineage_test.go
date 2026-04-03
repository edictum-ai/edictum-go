package approval

import "testing"

// --- SessionID on Request ---

func TestNewRequest_SessionIDDefault(t *testing.T) {
	r := NewRequest("req-sid-1", "Bash", nil, "approve?")
	if r.SessionID() != "" {
		t.Errorf("SessionID() = %q, want empty string", r.SessionID())
	}
}

func TestWithSessionID(t *testing.T) {
	r := NewRequest("req-sid-2", "Bash", nil, "approve?",
		WithSessionID("session-abc"),
	)
	if r.SessionID() != "session-abc" {
		t.Errorf("SessionID() = %q, want %q", r.SessionID(), "session-abc")
	}
}

func TestWithSessionID_Empty(t *testing.T) {
	r := NewRequest("req-sid-3", "Bash", nil, "approve?",
		WithSessionID(""),
	)
	if r.SessionID() != "" {
		t.Errorf("SessionID() = %q, want empty string", r.SessionID())
	}
}

func TestWithSessionID_ComposesWithOtherOptions(t *testing.T) {
	r := NewRequest("req-sid-4", "Bash", nil, "approve?",
		WithSessionID("session-xyz"),
		WithTimeoutEffect("block"),
	)
	if r.SessionID() != "session-xyz" {
		t.Errorf("SessionID() = %q, want %q", r.SessionID(), "session-xyz")
	}
	if r.TimeoutEffect() != "block" {
		t.Errorf("TimeoutEffect() = %q, want %q", r.TimeoutEffect(), "block")
	}
}
