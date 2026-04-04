package server

import (
	"context"
	"errors"
	"log"
	"math"
	"sync"
	"time"

	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/internal/deepcopy"
)

const defaultMaxBufferSize = 10_000

// AuditSink implements audit.Sink with batched delivery to the server.
// Events are buffered and flushed when the batch is full or on a timer.
//
// Buffer overflow policy: drop oldest events when max buffer is exceeded.
// Failed flush: events are restored to the buffer front (fail-closed).
type AuditSink struct {
	client        *Client
	batchSize     int
	flushInterval time.Duration
	maxBufferSize int

	mu     sync.Mutex
	buffer []map[string]any

	// stopCh is closed by Close to signal the flush goroutine to exit.
	stopCh chan struct{}
	// doneCh is closed when the flush goroutine has exited.
	doneCh chan struct{}
}

// AuditSinkOption configures a AuditSink.
type AuditSinkOption func(*AuditSink)

// WithBatchSize sets the number of events that triggers an immediate flush.
func WithBatchSize(n int) AuditSinkOption {
	return func(s *AuditSink) { s.batchSize = n }
}

// WithFlushInterval sets the periodic flush interval.
func WithFlushInterval(d time.Duration) AuditSinkOption {
	return func(s *AuditSink) { s.flushInterval = d }
}

// WithMaxBufferSize sets the maximum buffer size before dropping oldest events.
func WithMaxBufferSize(n int) AuditSinkOption {
	return func(s *AuditSink) { s.maxBufferSize = n }
}

// NewAuditSink creates a batching audit sink backed by the server.
func NewAuditSink(client *Client, opts ...AuditSinkOption) *AuditSink {
	s := &AuditSink{
		client:        client,
		batchSize:     50,
		flushInterval: 5 * time.Second,
		maxBufferSize: defaultMaxBufferSize,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	go s.flushLoop()
	return s
}

// Emit adds an audit event to the buffer. Flushes immediately if the
// buffer reaches batchSize.
func (s *AuditSink) Emit(ctx context.Context, event *audit.Event) error {
	payload := s.mapEvent(event)
	needsFlush := false

	s.mu.Lock()
	s.buffer = append(s.buffer, payload)
	if len(s.buffer) > s.maxBufferSize {
		dropped := len(s.buffer) - s.maxBufferSize
		s.buffer = s.buffer[dropped:]
	}
	needsFlush = len(s.buffer) >= s.batchSize
	s.mu.Unlock()

	if needsFlush {
		s.flush(ctx)
	}
	return nil
}

// Flush sends all buffered events to the server.
func (s *AuditSink) Flush(ctx context.Context) {
	s.flush(ctx)
}

// Close stops the flush goroutine and flushes remaining events.
// Safe to call multiple times.
func (s *AuditSink) Close(ctx context.Context) {
	s.mu.Lock()
	select {
	case <-s.stopCh:
		// Already closed.
		s.mu.Unlock()
		return
	default:
		close(s.stopCh)
	}
	s.mu.Unlock()
	<-s.doneCh
	s.flush(ctx)
}

// BufferLen returns the current number of buffered events. For testing.
func (s *AuditSink) BufferLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buffer)
}

// BufferCallIDs returns the call_id of each buffered event, in order. For testing.
func (s *AuditSink) BufferCallIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, len(s.buffer))
	for i, ev := range s.buffer {
		ids[i], _ = ev["call_id"].(string)
	}
	return ids
}

func (s *AuditSink) mapEvent(event *audit.Event) map[string]any {
	// bundle_name only existed inside the legacy nested payload shape.
	// The /v1/events contract does not include it as a top-level field.
	return map[string]any{
		"schema_version":          event.SchemaVersion,
		"call_id":                 event.CallID,
		"agent_id":                s.client.agentID,
		"tool_name":               event.ToolName,
		"tool_args":               deepcopy.Map(event.ToolArgs),
		"side_effect":             event.SideEffect,
		"environment":             eventEnvironment(event, s.client.Env()),
		"principal":               copyPrincipal(event.Principal),
		"action":                  string(event.Action),
		"decision_source":         event.DecisionSource,
		"decision_name":           event.DecisionName,
		"reason":                  event.Reason,
		"hooks_evaluated":         copyRecords(event.HooksEvaluated),
		"rules_evaluated":         copyRecords(event.RulesEvaluated),
		"mode":                    event.Mode,
		"policy_version":          event.PolicyVersion,
		"timestamp":               event.Timestamp.Format(time.RFC3339Nano),
		"run_id":                  event.RunID,
		"call_index":              event.CallIndex,
		"parent_call_id":          nullableString(event.ParentCallID),
		"session_id":              event.SessionID,
		"parent_session_id":       event.ParentSessionID,
		"workflow":                optionalMapValue(event.Workflow),
		"tool_success":            boolValue(event.ToolSuccess),
		"postconditions_passed":   boolValue(event.PostconditionsPassed),
		"duration_ms":             durationMsValue(event.DurationMs),
		"error":                   nullableString(event.Error),
		"result_summary":          nullableString(event.ResultSummary),
		"session_attempt_count":   intValue(event.SessionAttemptCount),
		"session_execution_count": intValue(event.SessionExecutionCount),
		"policy_error":            event.PolicyError,
	}
}

func eventEnvironment(event *audit.Event, fallback string) string {
	if event.Environment != "" {
		return event.Environment
	}
	return fallback
}

func copyPrincipal(principal any) any {
	if principal == nil {
		return nil
	}
	if pm, ok := principal.(map[string]any); ok {
		return deepcopy.Map(pm)
	}
	// Non-map principals are a pre-existing limitation: the current
	// audit payload only deep-copies generic records, not arbitrary structs.
	return principal
}

func copyRecords(records []map[string]any) []map[string]any {
	if records == nil {
		return nil
	}
	cp := make([]map[string]any, len(records))
	for i, record := range records {
		cp[i] = deepcopy.Map(record)
	}
	return cp
}

func optionalMapValue(value map[string]any) any {
	if value == nil {
		return nil
	}
	return deepcopy.Map(value)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func boolValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func durationMsValue(value *float64) any {
	if value == nil {
		return nil
	}
	return int64(math.Round(*value))
}

func intValue(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

// flush grabs the buffer under the lock and sends events outside the lock.
// On failure, events are restored to the buffer front.
func (s *AuditSink) flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	events := s.buffer
	s.buffer = nil
	s.mu.Unlock()

	_, err := s.client.Post(ctx, "/v1/events", map[string]any{"events": events})
	if err != nil {
		// 4xx client errors (except 429) are permanent failures — don't retry.
		// Restoring events on auth errors (401/403) would cause infinite retry
		// loops that eventually overflow the buffer and lose all events.
		var se *Error
		if errors.As(err, &se) && se.StatusCode >= 400 && se.StatusCode < 500 && se.StatusCode != 429 {
			log.Printf("server: permanently lost %d audit events due to client error: %v", len(events), err)
			return
		}
		log.Printf("server: failed to flush %d audit events, restoring to buffer: %v", len(events), err)
		s.restoreEvents(events)
	}
}

func (s *AuditSink) restoreEvents(events []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buffer = append(events, s.buffer...)
	if len(s.buffer) > s.maxBufferSize {
		// Truncate from the end (drop newest arrivals), preserving the
		// restored (older) events that need to be retried first.
		s.buffer = s.buffer[:s.maxBufferSize]
	}
}

func (s *AuditSink) flushLoop() {
	defer close(s.doneCh)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.flush(context.Background())
		}
	}
}
