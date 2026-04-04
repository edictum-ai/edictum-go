package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edictum-ai/edictum-go/audit"
)

func TestAuditSinkMapEventUsesFlatV1WireFormat(t *testing.T) {
	client, err := NewClient(ClientConfig{
		BaseURL: "https://api.edictum.test",
		APIKey:  "key",
		AgentID: "agent-123",
		Env:     "staging",
	})
	if err != nil {
		t.Fatal(err)
	}

	sink := NewAuditSink(client)
	defer sink.Close(context.Background())

	event := audit.NewEvent()
	event.Timestamp = time.Date(2026, 4, 4, 10, 30, 0, 123_000_000, time.UTC)
	event.RunID = "run-1"
	event.SessionID = "child-session"
	event.ParentSessionID = "parent-session"
	event.CallID = "call-1"
	event.CallIndex = 7
	event.ParentCallID = "call-0"
	event.ToolName = "Bash"
	event.ToolArgs = map[string]any{
		"command": "go test ./...",
		"nested":  map[string]any{"path": "server/audit_sink.go"},
	}
	event.SideEffect = "filesystem"
	event.Principal = map[string]any{
		"user_id": "mimi",
		"claims":  map[string]any{"role": "admin"},
	}
	event.Action = audit.ActionCallFailed
	event.DecisionSource = "workflow"
	event.DecisionName = "local-review"
	event.Reason = "Approval required before push"
	event.Workflow = map[string]any{
		"name":             "coding-guard",
		"version":          "2026-04-03",
		"active_stage":     "local-review",
		"completed_stages": []any{"read-context", "implement"},
		"pending_approval": map[string]any{"required": true, "stage_id": "local-review", "message": "Review the diff"},
		"last_blocked_action": map[string]any{
			"tool":      "Bash",
			"summary":   "git push origin HEAD",
			"message":   "Approval required before push",
			"timestamp": "2026-04-04T10:29:00Z",
		},
	}
	event.HooksEvaluated = []map[string]any{{"name": "pre-run", "passed": true}}
	event.RulesEvaluated = []map[string]any{{"id": "wf-1", "passed": false}}
	toolSuccess := false
	postconditionsPassed := false
	durationMs := 125.7
	attempts := 4
	executions := 2
	event.ToolSuccess = &toolSuccess
	event.PostconditionsPassed = &postconditionsPassed
	event.DurationMs = &durationMs
	event.Error = "exit status 1"
	event.ResultSummary = "go test ./..."
	event.SessionAttemptCount = &attempts
	event.SessionExecutionCount = &executions
	event.Mode = "enforce"
	event.PolicyVersion = "sha256:abc123"
	event.PolicyError = true

	payload := sink.mapEvent(&event)

	if _, ok := payload["payload"]; ok {
		t.Fatalf("legacy payload wrapper should be absent: %#v", payload)
	}
	if _, ok := payload["decision"]; ok {
		t.Fatalf("legacy decision field should be absent: %#v", payload)
	}
	if got := payload["schema_version"]; got != event.SchemaVersion {
		t.Fatalf("schema_version = %#v, want %q", got, event.SchemaVersion)
	}
	if got := payload["agent_id"]; got != "agent-123" {
		t.Fatalf("agent_id = %#v, want %q", got, "agent-123")
	}
	if got := payload["environment"]; got != "staging" {
		t.Fatalf("environment = %#v, want %q", got, "staging")
	}
	if got := payload["action"]; got != string(event.Action) {
		t.Fatalf("action = %#v, want %q", got, event.Action)
	}
	if got := payload["run_id"]; got != event.RunID {
		t.Fatalf("run_id = %#v, want %q", got, event.RunID)
	}
	if got := payload["parent_call_id"]; got != event.ParentCallID {
		t.Fatalf("parent_call_id = %#v, want %q", got, event.ParentCallID)
	}
	if got := payload["session_id"]; got != event.SessionID {
		t.Fatalf("session_id = %#v, want %q", got, event.SessionID)
	}
	if got := payload["parent_session_id"]; got != event.ParentSessionID {
		t.Fatalf("parent_session_id = %#v, want %q", got, event.ParentSessionID)
	}
	if got := payload["timestamp"]; got != event.Timestamp.Format(time.RFC3339Nano) {
		t.Fatalf("timestamp = %#v, want %q", got, event.Timestamp.Format(time.RFC3339Nano))
	}
	if got := payload["duration_ms"]; got != int64(126) {
		t.Fatalf("duration_ms = %#v, want %d", got, int64(126))
	}
	if got := payload["session_attempt_count"]; got != attempts {
		t.Fatalf("session_attempt_count = %#v, want %d", got, attempts)
	}
	if got := payload["session_execution_count"]; got != executions {
		t.Fatalf("session_execution_count = %#v, want %d", got, executions)
	}

	toolArgs, ok := payload["tool_args"].(map[string]any)
	if !ok {
		t.Fatalf("tool_args type = %T, want map[string]any", payload["tool_args"])
	}
	if toolArgs["command"] != "go test ./..." {
		t.Fatalf("tool_args.command = %#v, want %q", toolArgs["command"], "go test ./...")
	}
	workflow, ok := payload["workflow"].(map[string]any)
	if !ok {
		t.Fatalf("workflow type = %T, want map[string]any", payload["workflow"])
	}
	if workflow["active_stage"] != "local-review" {
		t.Fatalf("workflow.active_stage = %#v, want %q", workflow["active_stage"], "local-review")
	}
	pending, ok := workflow["pending_approval"].(map[string]any)
	if !ok {
		t.Fatalf("pending_approval type = %T, want map[string]any", workflow["pending_approval"])
	}
	if pending["required"] != true {
		t.Fatalf("pending_approval.required = %#v, want true", pending["required"])
	}
	rules, ok := payload["rules_evaluated"].([]map[string]any)
	if !ok {
		t.Fatalf("rules_evaluated type = %T, want []map[string]any", payload["rules_evaluated"])
	}
	if len(rules) != 1 || rules[0]["id"] != "wf-1" {
		t.Fatalf("rules_evaluated = %#v, want rule wf-1", rules)
	}

	toolArgs["command"] = "mutated"
	workflow["active_stage"] = "mutated"
	rules[0]["passed"] = true
	if event.ToolArgs["command"] != "go test ./..." {
		t.Fatalf("event.ToolArgs mutated through payload: %#v", event.ToolArgs)
	}
	if event.Workflow["active_stage"] != "local-review" {
		t.Fatalf("event.Workflow mutated through payload: %#v", event.Workflow)
	}
	if got, _ := event.RulesEvaluated[0]["passed"].(bool); got {
		t.Fatalf("event.RulesEvaluated mutated through payload: %#v", event.RulesEvaluated)
	}
}

func TestAuditSinkMapEventPreservesNilOptionalFields(t *testing.T) {
	client, err := NewClient(ClientConfig{
		BaseURL: "https://api.edictum.test",
		APIKey:  "key",
		AgentID: "agent-123",
		Env:     "staging",
	})
	if err != nil {
		t.Fatal(err)
	}

	sink := NewAuditSink(client)
	defer sink.Close(context.Background())

	event := audit.NewEvent()
	event.Timestamp = time.Date(2026, 4, 4, 10, 31, 0, 0, time.UTC)
	event.CallID = "call-nil"
	event.ToolName = "Read"
	event.ToolArgs = map[string]any{"path": "spec.md"}

	payload := sink.mapEvent(&event)

	if got := payload["environment"]; got != "staging" {
		t.Fatalf("environment = %#v, want %q", got, "staging")
	}
	if got := payload["parent_call_id"]; got != nil {
		t.Fatalf("parent_call_id = %#v, want nil", got)
	}
	if got := payload["tool_success"]; got != nil {
		t.Fatalf("tool_success = %#v, want nil", got)
	}
	if got := payload["postconditions_passed"]; got != nil {
		t.Fatalf("postconditions_passed = %#v, want nil", got)
	}
	if got := payload["duration_ms"]; got != nil {
		t.Fatalf("duration_ms = %#v, want nil", got)
	}
	if got := payload["error"]; got != nil {
		t.Fatalf("error = %#v, want nil", got)
	}
	if got := payload["result_summary"]; got != nil {
		t.Fatalf("result_summary = %#v, want nil", got)
	}
	if got := payload["session_attempt_count"]; got != nil {
		t.Fatalf("session_attempt_count = %#v, want nil", got)
	}
	if got := payload["session_execution_count"]; got != nil {
		t.Fatalf("session_execution_count = %#v, want nil", got)
	}
	if got := payload["workflow"]; got != nil {
		t.Fatalf("workflow = %#v, want nil", got)
	}
}

func TestDurationMsValueHandlesInvalidFloats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value float64
		want  any
	}{
		{name: "rounds finite values", value: 125.7, want: int64(126)},
		{name: "accepts min int64 boundary", value: -math.Ldexp(1, 63), want: int64(math.MinInt64)},
		{name: "rejects nan", value: math.NaN(), want: nil},
		{name: "rejects positive infinity", value: math.Inf(1), want: nil},
		{name: "rejects negative infinity", value: math.Inf(-1), want: nil},
		{name: "rejects positive overflow", value: math.Ldexp(1, 63), want: nil},
		{name: "rejects negative overflow", value: math.Nextafter(-math.Ldexp(1, 63), math.Inf(-1)), want: nil},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := durationMsValue(&tc.value)
			if got != tc.want {
				t.Fatalf("durationMsValue(%v) = %#v, want %#v", tc.value, got, tc.want)
			}
		})
	}
}

// --- 10.7: Audit batching ---

func TestAuditSinkBatching(t *testing.T) {
	var flushedCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		events, _ := body["events"].([]any)
		flushedCount.Add(int64(len(events)))
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	sink := NewAuditSink(client,
		WithBatchSize(3),
		WithFlushInterval(10*time.Second),
		WithMaxBufferSize(100),
	)
	defer sink.Close(context.Background())

	ctx := context.Background()
	for i := range 3 {
		event := audit.NewEvent()
		event.ToolName = "TestTool"
		event.CallID = string(rune('a' + i))
		if err := sink.Emit(ctx, &event); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	// Give flush a moment to complete.
	time.Sleep(100 * time.Millisecond)

	if n := flushedCount.Load(); n != 3 {
		t.Errorf("expected 3 flushed events, got %d", n)
	}
}

// --- 10.8: Buffer overflow ---

func TestAuditSinkBufferOverflow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	sink := NewAuditSink(client,
		WithBatchSize(1000), // high batch size so no auto-flush
		WithFlushInterval(10*time.Second),
		WithMaxBufferSize(5),
	)
	defer sink.Close(context.Background())

	ctx := context.Background()
	for i := range 10 {
		event := audit.NewEvent()
		event.ToolName = "TestTool"
		event.CallID = string(rune('a' + i))
		_ = sink.Emit(ctx, &event)
	}

	if n := sink.BufferLen(); n != 5 {
		t.Errorf("buffer should be capped at 5, got %d", n)
	}
}

// --- 10.9: Failed flush restores events ---

func TestAuditSinkFailedFlushRestoresEvents(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		APIKey:     "key",
		MaxRetries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	sink := NewAuditSink(client,
		WithBatchSize(1000),
		WithFlushInterval(10*time.Second),
		WithMaxBufferSize(100),
	)
	defer sink.Close(context.Background())

	ctx := context.Background()
	for i := range 3 {
		event := audit.NewEvent()
		event.ToolName = "TestTool"
		event.CallID = string(rune('a' + i))
		_ = sink.Emit(ctx, &event)
	}

	// Force a flush -- should fail and restore events.
	sink.Flush(ctx)

	if n := sink.BufferLen(); n != 3 {
		t.Errorf("after failed flush, buffer should have 3 events, got %d", n)
	}

	// Second flush should succeed.
	sink.Flush(ctx)

	if n := sink.BufferLen(); n != 0 {
		t.Errorf("after successful flush, buffer should be empty, got %d", n)
	}
}

// --- Restore overflow: newest dropped, oldest kept ---

func TestAuditSinkRestoreOverflow_DropsNewest(t *testing.T) {
	// Scenario: flush grabs 3 events and fails. Between the grab and the
	// restore, new events are emitted into the buffer. When restoreEvents
	// prepends the failed events and total exceeds maxBufferSize, the
	// NEWEST events (from the end) are dropped — not the restored oldest ones.
	//
	// We use a handler that blocks on the first call until we signal it,
	// giving us time to emit new events into the buffer while the flush
	// is in-flight.
	flushStarted := make(chan struct{})
	flushUnblock := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Signal that flush HTTP call has started.
		select {
		case flushStarted <- struct{}{}:
		default:
		}
		// Wait until test says to proceed.
		<-flushUnblock
		// Return error so events are restored.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		APIKey:     "key",
		MaxRetries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	sink := NewAuditSink(client,
		WithBatchSize(1000), // no auto-flush
		WithFlushInterval(10*time.Second),
		WithMaxBufferSize(5),
	)
	defer sink.Close(context.Background())

	ctx := context.Background()

	// Emit 3 "old" events.
	for i := range 3 {
		event := audit.NewEvent()
		event.ToolName = "TestTool"
		event.CallID = "old-" + string(rune('0'+i))
		_ = sink.Emit(ctx, &event)
	}

	// Start flush in background. It grabs 3 events (buffer empty), then
	// blocks on the HTTP call.
	flushDone := make(chan struct{})
	go func() {
		sink.Flush(ctx)
		close(flushDone)
	}()

	// Wait for flush HTTP call to start (buffer is now empty).
	<-flushStarted

	// Emit 4 "new" events while flush is in-flight. Buffer: [new-0..new-3].
	for i := range 4 {
		event := audit.NewEvent()
		event.ToolName = "TestTool"
		event.CallID = "new-" + string(rune('0'+i))
		_ = sink.Emit(ctx, &event)
	}

	// Unblock the flush -- it will fail and call restoreEvents.
	// restoreEvents prepends [old-0, old-1, old-2] to [new-0..new-3] = 7 total.
	// maxBufferSize=5, so it truncates from end: drops new-2, new-3.
	close(flushUnblock)
	<-flushDone

	if n := sink.BufferLen(); n != 5 {
		t.Fatalf("expected buffer capped at 5, got %d", n)
	}

	// Verify: the 3 restored oldest events come first, then only the
	// first 2 new events. The newest (new-2, new-3) were dropped.
	ids := sink.BufferCallIDs()
	want := []string{"old-0", "old-1", "old-2", "new-0", "new-1"}
	for i, w := range want {
		if ids[i] != w {
			t.Errorf("buffer[%d] = %q, want %q", i, ids[i], w)
		}
	}
}

func TestAuditSinkPermanentDropOn4xx(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(fmt.Sprintf("HTTP%d", code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
				_, _ = w.Write([]byte("error"))
			}))
			defer srv.Close()

			client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key", MaxRetries: 1})
			if err != nil {
				t.Fatal(err)
			}
			sink := NewAuditSink(client,
				WithBatchSize(1000),
				WithFlushInterval(10*time.Second),
				WithMaxBufferSize(100),
			)
			defer sink.Close(context.Background())

			ctx := context.Background()
			event := audit.NewEvent()
			event.ToolName = "TestTool"
			_ = sink.Emit(ctx, &event)

			sink.Flush(ctx)

			if n := sink.BufferLen(); n != 0 {
				t.Errorf("HTTP %d: expected 0 buffered events after permanent drop, got %d", code, n)
			}
		})
	}
}

func TestAuditSinkRestoreOn429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("rate limited"))
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key", MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	sink := NewAuditSink(client,
		WithBatchSize(1000),
		WithFlushInterval(10*time.Second),
		WithMaxBufferSize(100),
	)
	defer sink.Close(context.Background())

	ctx := context.Background()
	event := audit.NewEvent()
	event.ToolName = "TestTool"
	_ = sink.Emit(ctx, &event)

	sink.Flush(ctx)

	if n := sink.BufferLen(); n != 1 {
		t.Errorf("HTTP 429: expected 1 buffered event after restore, got %d", n)
	}
}
