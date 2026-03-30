package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// --- 10.1: TLS enforcement ---

func TestTLSEnforcementRejectsHTTPToNonLoopback(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL: "http://remote-host.example.com:8080",
		APIKey:  "test-key",
	})
	if err == nil {
		t.Fatal("expected error for plaintext HTTP to non-loopback host")
	}
	if !strings.Contains(err.Error(), "refusing plaintext HTTP") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTLSEnforcementAllowsLocalhost(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "[::1]"} {
		_, err := NewClient(ClientConfig{
			BaseURL: "http://" + host + ":8080",
			APIKey:  "test-key",
		})
		if err != nil {
			t.Errorf("unexpected error for %s: %v", host, err)
		}
	}
}

func TestTLSEnforcementAllowsHTTPS(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL: "https://remote-host.example.com",
		APIKey:  "test-key",
	})
	if err != nil {
		t.Errorf("unexpected error for HTTPS: %v", err)
	}
}

func TestTLSEnforcementAllowInsecureOverride(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL:       "http://remote-host.example.com",
		APIKey:        "test-key",
		AllowInsecure: true,
	})
	if err != nil {
		t.Errorf("unexpected error with AllowInsecure: %v", err)
	}
}

// --- 10.2: Safe identifier validation ---

func TestIdentifierValidation(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		env     string
		bundle  string
		wantErr string
	}{
		{"valid defaults", "agent1", "production", "", ""},
		{"valid with dots", "my.agent-1", "staging_env", "bundle.v2", ""},
		{"empty agent uses default", "", "prod", "", ""},
		{"invalid agent_id", "../../etc", "prod", "", "invalid agent_id"},
		{"invalid env", "agent1", "rm -rf /", "", "invalid env"},
		{"invalid bundle_name", "agent1", "prod", "../escape", "invalid bundle_name"},
		{"agent too long", strings.Repeat("a", 200), "prod", "", "invalid agent_id"},
		{"agent starts with dot", ".hidden", "prod", "", "invalid agent_id"},
		{"agent with spaces", "my agent", "prod", "", "invalid agent_id"},
		{"agent with null byte", "agent\x00id", "prod", "", "invalid agent_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ClientConfig{
				BaseURL: "http://localhost:8080",
				APIKey:  "key",
				AgentID: tt.agentID,
				Env:     tt.env,
			}
			if tt.bundle != "" {
				cfg.BundleName = tt.bundle
			}
			_, err := NewClient(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("got %v, want error containing %q", err, tt.wantErr)
				}
			}
		})
	}
}

// --- 10.3: Tag size limits ---

func TestTagSizeLimits(t *testing.T) {
	t.Run("too many tags", func(t *testing.T) {
		tags := make(map[string]string, 65)
		for i := range 65 {
			tags[string(rune('a'+i%26))+strings.Repeat("x", i)] = "v"
		}
		_, err := NewClient(ClientConfig{
			BaseURL: "http://localhost:8080",
			APIKey:  "key",
			Tags:    tags,
		})
		if err == nil {
			t.Fatal("expected error for too many tags")
		}
		if !strings.Contains(err.Error(), "too many tags") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("key too long", func(t *testing.T) {
		_, err := NewClient(ClientConfig{
			BaseURL: "http://localhost:8080",
			APIKey:  "key",
			Tags:    map[string]string{strings.Repeat("k", 129): "v"},
		})
		if err == nil {
			t.Fatal("expected error for key too long")
		}
		if !strings.Contains(err.Error(), "tag key too long") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("value too long", func(t *testing.T) {
		_, err := NewClient(ClientConfig{
			BaseURL: "http://localhost:8080",
			APIKey:  "key",
			Tags:    map[string]string{"k": strings.Repeat("v", 257)},
		})
		if err == nil {
			t.Fatal("expected error for value too long")
		}
		if !strings.Contains(err.Error(), "tag value too long") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("64 tags allowed", func(t *testing.T) {
		tags := make(map[string]string, 64)
		for i := range 64 {
			tags["key"+strings.Repeat("x", i)] = "v"
		}
		_, err := NewClient(ClientConfig{
			BaseURL: "http://localhost:8080",
			APIKey:  "key",
			Tags:    tags,
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// --- 10.4: Fail-closed on network error ---

func TestFailClosedOnNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
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

	_, err = client.Get(context.Background(), "/v1/test")
	if err == nil {
		t.Fatal("expected error on network failure, got nil")
	}
}

// --- 10.5: 404 returns nil ---

func TestGetReturnsNilOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"not found"}`))
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(context.Background(), "/v1/sessions/missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response for 404, got %v", resp)
	}
}

// --- Retry on 5xx ---

func TestRetryOn5xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		APIKey:     "key",
		MaxRetries: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("unexpected response: %v", resp)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

// --- Auth header ---

func TestBearerTokenAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "secret-token"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer secret-token")
	}
}
