package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edictum-ai/edictum-go/audit"
)

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
