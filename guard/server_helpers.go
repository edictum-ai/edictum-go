package guard

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/edictum-ai/edictum-go/server"
)

// notifyingReloader wraps a Reloader and closes readyCh on the first
// successful reload. Used for server-assigned mode to signal FromServer
// that the initial bundle has arrived.
type notifyingReloader struct {
	inner   server.Reloader
	once    sync.Once
	readyCh chan struct{}
}

func (r *notifyingReloader) ReloadFromYAML(yamlBytes []byte) error {
	err := r.inner.ReloadFromYAML(yamlBytes)
	if err == nil {
		r.once.Do(func() { close(r.readyCh) })
	}
	return err
}

// startWatcher creates and starts the SSE watcher goroutine.
// Writes to g.sseCloser and g.watchCancel are protected by g.mu.
func startWatcher(g *Guard, client *server.Client, fc *factoryCfg) {
	var watcherOpts []server.SSEWatcherOption
	if fc.signingPublicKey != "" {
		watcherOpts = append(watcherOpts, server.WithPublicKey(fc.signingPublicKey))
	}
	watcher := server.NewSSEWatcher(client, g, watcherOpts...)
	watchCtx, watchCancel := context.WithCancel(context.Background())

	g.mu.Lock()
	g.sseCloser = watcher
	g.watchCancel = watchCancel
	g.mu.Unlock()

	go watcher.Watch(watchCtx) //nolint:errcheck // background watcher logs errors
}

func decodeYAMLResponse(resp map[string]any) ([]byte, error) {
	yamlB64, _ := resp["yaml_bytes"].(string)
	if yamlB64 == "" {
		return nil, fmt.Errorf("server response missing yaml_bytes")
	}
	decoded, err := base64.StdEncoding.DecodeString(yamlB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in yaml_bytes: %w", err)
	}
	return decoded, nil
}

func verifyIfNeeded(fc *factoryCfg, resp map[string]any, bundleYAML []byte) error {
	if !fc.verifySignatures {
		return nil
	}
	sigB64, _ := resp["signature"].(string)
	if sigB64 == "" {
		return &server.BundleVerificationError{
			Message: "server response missing signature but verify_signatures is true",
		}
	}
	return server.VerifyBundleSignature(bundleYAML, sigB64, fc.signingPublicKey)
}

// Close stops the SSE watcher and flushes audit events.
// Safe to call on guards not created by FromServer (no-op).
// Safe to call multiple times concurrently.
func (g *Guard) Close(ctx context.Context) {
	g.mu.RLock()
	cancel := g.watchCancel
	closer := g.sseCloser
	sink := g.auditSink
	g.mu.RUnlock()

	if cancel != nil {
		cancel()
	}
	if closer != nil {
		closer.Close()
	}
	type flusher interface {
		Close(context.Context)
	}
	if f, ok := sink.(flusher); ok {
		f.Close(ctx)
	}
}
