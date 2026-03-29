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
	return s.getCounter(ctx, s.key("execs"))
}

// ToolExecutionCount returns the execution count for a specific tool.
func (s *Session) ToolExecutionCount(ctx context.Context, tool string) (int, error) {
	if err := validateKeyComponent(tool); err != nil {
		return 0, fmt.Errorf("invalid tool name: %w", err)
	}
	return s.getCounter(ctx, s.key("tool:"+tool))
}

// ConsecutiveFailures returns the consecutive failure count.
func (s *Session) ConsecutiveFailures(ctx context.Context) (int, error) {
	return s.getCounter(ctx, s.key("consec_fail"))
}

// BatchGetCounters pre-fetches multiple session counters in a single
// backend call. Returns a map with keys "attempts", "execs", and
// optionally "tool:{name}" if includeTool is non-empty.
//
// Uses BatchGetter interface when available (single round trip for
// server backends). Falls back to individual Get calls otherwise.
func (s *Session) BatchGetCounters(ctx context.Context, includeTool string) (map[string]int, error) {
	keys := []string{
		s.key("attempts"),
		s.key("execs"),
	}
	labels := []string{"attempts", "execs"}

	if includeTool != "" {
		if err := validateKeyComponent(includeTool); err != nil {
			return nil, fmt.Errorf("invalid tool name: %w", err)
		}
		keys = append(keys, s.key("tool:"+includeTool))
		labels = append(labels, "tool:"+includeTool)
	}

	var raw map[string]string
	if bg, ok := s.backend.(BatchGetter); ok {
		var err error
		raw, err = bg.BatchGet(ctx, keys)
		if err != nil {
			return nil, err
		}
	} else {
		raw = make(map[string]string, len(keys))
		for _, key := range keys {
			val, err := s.backend.Get(ctx, key)
			if err != nil {
				return nil, err
			}
			raw[key] = val
		}
	}

	result := make(map[string]int, len(keys))
	for i, key := range keys {
		v, err := parseCounter(raw[key])
		if err != nil {
			return nil, fmt.Errorf("corrupt counter %q: %w", labels[i], err)
		}
		result[labels[i]] = v
	}
	return result, nil
}

// GetValue returns a namespaced session-scoped value.
func (s *Session) GetValue(ctx context.Context, name string) (string, error) {
	if err := validateKeyComponent(name); err != nil {
		return "", fmt.Errorf("invalid session value name: %w", err)
	}
	return s.backend.Get(ctx, s.key(name))
}

// SetValue stores a namespaced session-scoped value.
func (s *Session) SetValue(ctx context.Context, name, value string) error {
	if err := validateKeyComponent(name); err != nil {
		return fmt.Errorf("invalid session value name: %w", err)
	}
	return s.backend.Set(ctx, s.key(name), value)
}

// DeleteValue removes a namespaced session-scoped value.
func (s *Session) DeleteValue(ctx context.Context, name string) error {
	if err := validateKeyComponent(name); err != nil {
		return fmt.Errorf("invalid session value name: %w", err)
	}
	return s.backend.Delete(ctx, s.key(name))
}

func (s *Session) getCounter(ctx context.Context, key string) (int, error) {
	val, err := s.backend.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	return parseCounter(val)
}

func (s *Session) key(counter string) string {
	return fmt.Sprintf("s:%s:%s", s.sessionID, counter)
}

// parseCounter parses a counter value string. Empty strings return 0
// (counter not yet initialized). Non-numeric values return an error
// to fail closed per security policy.
func parseCounter(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("corrupt counter value %q: %w", s, err)
	}
	return v, nil
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
