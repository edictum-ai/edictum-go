// Package session provides session-level state management and counters.
package session

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

// StorageBackend defines the interface for persistent state storage.
type StorageBackend interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
	Increment(ctx context.Context, key string, amount int) (int, error)
}

// BatchGetter is an optional interface for backends that support batch reads.
type BatchGetter interface {
	BatchGet(ctx context.Context, keys []string) (map[string]string, error)
}

// Session tracks per-session governance state (attempts, executions, failures).
type Session struct {
	sessionID string
	backend   StorageBackend
}

// New creates a new Session with the given ID and backend.
func New(sessionID string, backend StorageBackend) (*Session, error) {
	if err := validateKeyComponent(sessionID); err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}
	return &Session{sessionID: sessionID, backend: backend}, nil
}

// ID returns the session ID.
func (s *Session) ID() string { return s.sessionID }

// IncrementAttempts increments the attempt counter and returns the new value.
func (s *Session) IncrementAttempts(ctx context.Context) (int, error) {
	return s.backend.Increment(ctx, s.key("attempts"), 1)
}

// AttemptCount returns the current attempt count.
func (s *Session) AttemptCount(ctx context.Context) (int, error) {
	val, err := s.backend.Get(ctx, s.key("attempts"))
	if err != nil {
		return 0, err
	}
	if val == "" {
		return 0, nil
	}
	var count int
	_, err = fmt.Sscanf(val, "%d", &count)
	return count, err
}

// RecordExecution records a tool execution and updates counters.
func (s *Session) RecordExecution(ctx context.Context, toolName string, success bool) error {
	if err := validateKeyComponent(toolName); err != nil {
		return fmt.Errorf("invalid tool name: %w", err)
	}

	if _, err := s.backend.Increment(ctx, s.key("execs"), 1); err != nil {
		return err
	}
	if _, err := s.backend.Increment(ctx, s.key("tool:"+toolName), 1); err != nil {
		return err
	}

	if success {
		return s.backend.Set(ctx, s.key("consec_fail"), "0")
	}
	_, err := s.backend.Increment(ctx, s.key("consec_fail"), 1)
	return err
}

// ExecutionCount returns the total execution count.
func (s *Session) ExecutionCount(ctx context.Context) (int, error) {
	val, err := s.backend.Get(ctx, s.key("execs"))
	if err != nil {
		return 0, err
	}
	if val == "" {
		return 0, nil
	}
	var count int
	_, err = fmt.Sscanf(val, "%d", &count)
	return count, err
}

func (s *Session) key(counter string) string {
	return fmt.Sprintf("s:%s:%s", s.sessionID, counter)
}

func validateKeyComponent(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(s) > 10000 {
		return fmt.Errorf("must not exceed 10000 characters")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	if strings.ContainsAny(s, "/\\") {
		return fmt.Errorf("must not contain path separators")
	}
	return nil
}
