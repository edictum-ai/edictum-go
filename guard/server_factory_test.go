package guard

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edictum-ai/edictum-go/server"
)

const validBundleYAML = `apiVersion: edictum/v2
kind: Ruleset
defaults:
  mode: enforce
rules:
  - id: no-rm
    type: pre
    tool: Bash
    when:
      "args.command":
        contains: "rm -rf"
    then:
      action: block
      message: "Cannot run rm -rf"
`

// bundleServer returns an httptest.Server that serves a valid base64-encoded
// bundle at /api/v1/bundles/{name}/current. It validates the Authorization
// header and records the last request for inspection.
func bundleServer(t *testing.T, bundleName, apiKey string) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var lastReq atomic.Value
	yamlB64 := base64.StdEncoding.EncodeToString([]byte(validBundleYAML))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReq.Store(r)
		expectedPath := "/api/v1/bundles/" + bundleName + "/current"
		if r.URL.Path != expectedPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"not found"}`))
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"yaml_bytes": yamlB64,
		})
	}))
	return srv, &lastReq
}

// signedBundleServer returns a server that includes an Ed25519 signature
// in the response. If invalidSig is true, it returns a corrupted signature.
// If missingSig is true, no signature is included.
func signedBundleServer(
	t *testing.T,
	bundleName, apiKey string,
	privateKey ed25519.PrivateKey,
	invalidSig, missingSig bool,
) *httptest.Server {
	t.Helper()
	yamlBytes := []byte(validBundleYAML)
	yamlB64 := base64.StdEncoding.EncodeToString(yamlBytes)

	sig := ed25519.Sign(privateKey, yamlBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if invalidSig {
		// Flip every byte to make an obviously invalid signature.
		corrupted := make([]byte, len(sig))
		for i := range sig {
			corrupted[i] = sig[i] ^ 0xff
		}
		sigB64 = base64.StdEncoding.EncodeToString(corrupted)
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/api/v1/bundles/" + bundleName + "/current"
		if r.URL.Path != expectedPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := map[string]string{"yaml_bytes": yamlB64}
		if !missingSig {
			resp["signature"] = sigB64
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestFromServer_BasicConnection(t *testing.T) {
	srv, _ := bundleServer(t, "my-bundle", "test-key")
	defer srv.Close()

	g, err := FromServer(
		srv.URL, "test-key", "agent-1",
		WithBundleName("my-bundle"),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("FromServer returned error: %v", err)
	}
	defer g.Close(context.Background())

	// Guard should have a non-empty policy version (SHA-256 of the YAML).
	if g.PolicyVersion() == "" {
		t.Error("expected non-empty policy version")
	}

	// The bundle contains one precondition; verify the guard has rules.
	g.mu.RLock()
	nPre := len(g.state.preconditions)
	g.mu.RUnlock()
	if nPre == 0 {
		t.Error("expected at least one precondition from the bundle")
	}
}

func TestFromServer_EnvironmentPassthrough(t *testing.T) {
	// The client sends the environment to the server via the client config.
	// We verify by inspecting the Guard's serverClient after construction.
	srv, _ := bundleServer(t, "env-bundle", "key-env")
	defer srv.Close()

	g, err := FromServer(
		srv.URL, "key-env", "agent-env",
		WithBundleName("env-bundle"),
		WithEnvironment("staging"),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("FromServer returned error: %v", err)
	}
	defer g.Close(context.Background())

	// The guard's mode should reflect the bundle default ("enforce").
	// Environment passthrough is validated by the fact that construction
	// succeeded -- the client was configured with env="staging".
	// We can also verify the guard's environment field directly.
	g.mu.RLock()
	env := g.environment
	g.mu.RUnlock()
	if env != "staging" {
		t.Errorf("environment = %q, want %q", env, "staging")
	}
}

func TestFromServer_ModeOverride(t *testing.T) {
	srv, _ := bundleServer(t, "mode-bundle", "key-mode")
	defer srv.Close()

	g, err := FromServer(
		srv.URL, "key-mode", "agent-mode",
		WithBundleName("mode-bundle"),
		WithMode("observe"),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("FromServer returned error: %v", err)
	}
	defer g.Close(context.Background())

	// The bundle defaults to "enforce", but user override should win.
	if got := g.Mode(); got != "observe" {
		t.Errorf("Mode() = %q, want %q", got, "observe")
	}
}

func TestFromServer_VerifySignatures_ValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	srv := signedBundleServer(t, "sig-bundle", "key-sig", priv, false, false)
	defer srv.Close()

	g, err := FromServer(
		srv.URL, "key-sig", "agent-sig",
		WithBundleName("sig-bundle"),
		WithVerifySignatures(pubHex),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("FromServer returned error: %v", err)
	}
	defer g.Close(context.Background())

	if g.PolicyVersion() == "" {
		t.Error("expected non-empty policy version after valid signature")
	}
}

func TestFromServer_VerifySignatures_InvalidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	srv := signedBundleServer(t, "sig-bundle", "key-sig", priv, true, false)
	defer srv.Close()

	_, err = FromServer(
		srv.URL, "key-sig", "agent-sig",
		WithBundleName("sig-bundle"),
		WithVerifySignatures(pubHex),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	var bve *server.BundleVerificationError
	if !errors.As(err, &bve) {
		t.Errorf("expected *BundleVerificationError, got %T: %v", err, err)
	}
}

func TestFromServer_VerifySignatures_MissingSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	srv := signedBundleServer(t, "sig-bundle", "key-sig", priv, false, true)
	defer srv.Close()

	_, err = FromServer(
		srv.URL, "key-sig", "agent-sig",
		WithBundleName("sig-bundle"),
		WithVerifySignatures(pubHex),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
	var bve *server.BundleVerificationError
	if !errors.As(err, &bve) {
		t.Errorf("expected *BundleVerificationError, got %T: %v", err, err)
	}
}

func TestFromServer_BundleNameRequired(t *testing.T) {
	_, err := FromServer(
		"http://localhost:9999", "key", "agent",
		WithAutoWatch(false),
		// No WithBundleName -- should fail.
	)
	if err == nil {
		t.Fatal("expected error when WithBundleName is missing")
	}
	if !strings.Contains(err.Error(), "auto_watch must be true") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "auto_watch must be true")
	}
}

func TestFromServer_VerifySignaturesRequiresKey(t *testing.T) {
	// WithVerifySignatures with an empty key should fail at validation.
	_, err := FromServer(
		"http://localhost:9999", "key", "agent",
		WithBundleName("bundle"),
		WithVerifySignatures(""),
		WithAutoWatch(false),
	)
	if err == nil {
		t.Fatal("expected error when verify_signatures is true but key is empty")
	}
	if !strings.Contains(err.Error(), "signing public key is required") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "signing public key is required")
	}
}

func TestFromServer_InvalidURL(t *testing.T) {
	_, err := FromServer(
		"://not-a-url", "key", "agent",
		WithBundleName("bundle"),
		WithAutoWatch(false),
	)
	if err == nil {
		t.Fatal("expected error for malformed URL")
	}
	// The error should come from the client URL validation.
	if !strings.Contains(err.Error(), "FromServer") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "FromServer")
	}
}

func TestFromServer_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"internal server error"}`))
	}))
	defer srv.Close()

	_, err := FromServer(
		srv.URL, "key", "agent",
		WithBundleName("bundle"),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err == nil {
		t.Fatal("expected error when server returns 500")
	}
	if !strings.Contains(err.Error(), "failed to fetch") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "failed to fetch")
	}
}

func TestFromServer_BundleNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"not found"}`))
	}))
	defer srv.Close()

	_, err := FromServer(
		srv.URL, "key", "agent",
		WithBundleName("nonexistent"),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err == nil {
		t.Fatal("expected error when bundle is not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "not found")
	}
}

func TestFromServer_Close(t *testing.T) {
	srv, _ := bundleServer(t, "close-bundle", "key-close")
	defer srv.Close()

	g, err := FromServer(
		srv.URL, "key-close", "agent-close",
		WithBundleName("close-bundle"),
		WithAutoWatch(false),
		WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("FromServer returned error: %v", err)
	}

	// Close should be safe to call.
	g.Close(context.Background())

	// Close should be safe to call multiple times.
	g.Close(context.Background())

	// Guard should still be usable for reads after Close (no panic).
	_ = g.Mode()
	_ = g.PolicyVersion()
}

func TestFromServer_ServerAssignedMode(t *testing.T) {
	yamlB64 := base64.StdEncoding.EncodeToString([]byte(validBundleYAML))

	// Gate: bundle endpoint blocks until SSE has pushed the assignment.
	bundleReady := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/bundles/auto-bundle/current":
			<-bundleReady // wait until SSE has pushed the assignment
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"yaml_bytes": yamlB64})

		case strings.HasPrefix(r.URL.Path, "/api/v1/bundles/") && strings.HasSuffix(r.URL.Path, "/current"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"not found"}`))

		case strings.HasPrefix(r.URL.Path, "/api/v1/stream"):
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}
			data, _ := json.Marshal(map[string]any{
				"_assignment_changed": true,
				"bundle_name":         "auto-bundle",
			})
			// Enable the bundle endpoint before sending the SSE event.
			select {
			case <-bundleReady:
			default:
				close(bundleReady)
			}
			_, _ = fmt.Fprintf(w, "event: contract_update\ndata: %s\n\n", data)
			flusher.Flush()
			time.Sleep(2 * time.Second)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	g, err := FromServer(
		srv.URL, "test-key", "agent-1",
		// No WithBundleName -- server-assigned mode.
		WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("FromServer returned error: %v", err)
	}
	defer g.Close(context.Background())

	g.mu.RLock()
	nPre := len(g.state.preconditions)
	g.mu.RUnlock()
	if nPre == 0 {
		t.Error("expected at least one precondition from the assigned bundle")
	}
}
