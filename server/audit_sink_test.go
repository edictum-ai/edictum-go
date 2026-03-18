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
