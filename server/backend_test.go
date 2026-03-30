package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- 10.6: batch_get fallback ---

func TestBackendBatchGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sessions/batch" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": map[string]any{
					"key1": "val1",
					"key2": "val2",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(client)
	result, err := backend.BatchGet(context.Background(), []string{"key1", "key2", "key3"})
	if err != nil {
		t.Fatalf("BatchGet: %v", err)
	}
	if result["key1"] != "val1" {
		t.Errorf("key1: got %q, want %q", result["key1"], "val1")
	}
	if result["key2"] != "val2" {
		t.Errorf("key2: got %q, want %q", result["key2"], "val2")
	}
	if result["key3"] != "" {
		t.Errorf("key3: got %q, want empty", result["key3"])
	}
}

func TestBackendBatchGetFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sessions/batch" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("not supported"))
			return
		}
		if r.URL.Path == "/v1/sessions/k1" {
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "v1"})
			return
		}
		if r.URL.Path == "/v1/sessions/k2" {
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "v2"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(client)
	result, err := backend.BatchGet(context.Background(), []string{"k1", "k2"})
	if err != nil {
		t.Fatalf("BatchGet fallback: %v", err)
	}
	if result["k1"] != "v1" {
		t.Errorf("k1: got %q, want %q", result["k1"], "v1")
	}
	if result["k2"] != "v2" {
		t.Errorf("k2: got %q, want %q", result["k2"], "v2")
	}
}

func TestBackendGetSetDelete(t *testing.T) {
	var storedValue string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if storedValue == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"value": storedValue})
		case http.MethodPut:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			storedValue = body["value"]
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case http.MethodDelete:
			storedValue = ""
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	backend := NewBackend(client)

	val, err := backend.Get(ctx, "mykey")
	if err != nil {
		t.Fatalf("Get missing: %v", err)
	}
	if val != "" {
		t.Errorf("Get missing: got %q, want empty", val)
	}

	if err := backend.Set(ctx, "mykey", "hello"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err = backend.Get(ctx, "mykey")
	if err != nil {
		t.Fatalf("Get after set: %v", err)
	}
	if val != "hello" {
		t.Errorf("Get after set: got %q, want %q", val, "hello")
	}

	if err := backend.Delete(ctx, "mykey"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	val, err = backend.Get(ctx, "mykey")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if val != "" {
		t.Errorf("Get after delete: got %q, want empty", val)
	}
}

func TestBackendIncrement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"value": 42.0})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(client)
	val, err := backend.Increment(context.Background(), "counter", 1)
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if val != 42 {
		t.Errorf("Increment: got %d, want 42", val)
	}
}

func TestBackendFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
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

	backend := NewBackend(client)
	_, err = backend.Get(context.Background(), "key")
	if err == nil {
		t.Fatal("expected error on 500, got nil -- fail-closed violated")
	}
}
