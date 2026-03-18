package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// mockReloader records calls to ReloadFromYAML.
type mockReloader struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (m *mockReloader) ReloadFromYAML(yamlBytes []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, string(yamlBytes))
	return m.err
}

func (m *mockReloader) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *mockReloader) lastCall() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return ""
	}
	return m.calls[len(m.calls)-1]
}

// --- 10.10: SSE hot-reload ---

func TestSSEHotReload(t *testing.T) {
	bundleYAML := "apiVersion: edictum/v1\nkind: ContractBundle"
	bundleJSON, _ := json.Marshal(map[string]string{"yaml": bundleYAML})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		_, _ = fmt.Fprintf(w, "event: contract_update\ndata: %s\n\n", bundleJSON)
		flusher.Flush()

		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	reloader := &mockReloader{}
	watcher := NewSSEWatcher(client, reloader)
	defer watcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() { _ = watcher.Watch(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reloader.callCount() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if reloader.callCount() == 0 {
		t.Fatal("expected at least one reload call")
	}
	if got := reloader.lastCall(); got != bundleYAML {
		t.Errorf("reload YAML: got %q, want %q", got, bundleYAML)
	}
}

// --- 10.11: SSE reconnect backoff ---

func TestSSEReconnectBackoff(t *testing.T) {
	var connectCount int
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		connectCount++
		n := connectCount
		mu.Unlock()

		if n <= 2 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			_ = conn.Close()
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		_, _ = fmt.Fprintf(w, "event: contract_update\ndata: {\"yaml\":\"ok\"}\n\n")
		flusher.Flush()
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{BaseURL: srv.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}

	reloader := &mockReloader{}
	watcher := NewSSEWatcher(client, reloader,
		WithReconnectDelay(50*time.Millisecond),
		WithMaxReconnectDelay(200*time.Millisecond),
	)
	defer watcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = watcher.Watch(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if reloader.callCount() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	n := connectCount
	mu.Unlock()

	if n < 3 {
		t.Errorf("expected at least 3 connect attempts, got %d", n)
	}
	if reloader.callCount() == 0 {
		t.Fatal("expected reload after reconnect")
	}
}

// --- 10.12: Ed25519 verification ---

func TestEd25519Verification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	yamlBytes := []byte("apiVersion: edictum/v1\nkind: ContractBundle")
	sig := ed25519.Sign(priv, yamlBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	pubHex := hex.EncodeToString(pub)

	t.Run("valid signature", func(t *testing.T) {
		err := VerifyBundleSignature(yamlBytes, sigB64, pubHex)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("tampered content", func(t *testing.T) {
		err := VerifyBundleSignature([]byte("tampered"), sigB64, pubHex)
		if err == nil {
			t.Fatal("expected error for tampered content")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherPub, _, _ := ed25519.GenerateKey(nil)
		err := VerifyBundleSignature(yamlBytes, sigB64, hex.EncodeToString(otherPub))
		if err == nil {
			t.Fatal("expected error for wrong key")
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		err := VerifyBundleSignature(yamlBytes, "", pubHex)
		if err == nil {
			t.Fatal("expected error for empty signature")
		}
	})

	t.Run("empty public key", func(t *testing.T) {
		err := VerifyBundleSignature(yamlBytes, sigB64, "")
		if err == nil {
			t.Fatal("expected error for empty public key")
		}
	})
}

// --- 10.13: BundleVerificationError ---

func TestBundleVerificationError(t *testing.T) {
	err := VerifyBundleSignature([]byte("data"), "invalid-base64!", "aabbcc")
	if err == nil {
		t.Fatal("expected error")
	}
	var bve *BundleVerificationError
	if !errors.As(err, &bve) {
		t.Errorf("expected *BundleVerificationError, got %T", err)
	}
}
