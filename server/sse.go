package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"
)

// Reloader is the interface for hot-reloading contract bundles.
// Guard implements this via its Reload method (added by the server package).
type Reloader interface {
	ReloadFromYAML(yamlBytes []byte) error
}

// SSEWatcher connects to the server's SSE endpoint for contract updates.
// On receiving a new bundle, it calls the Reloader. Reconnects with
// exponential backoff on disconnect.
type SSEWatcher struct {
	client            *Client
	reloader          Reloader
	publicKeyHex      string // optional: Ed25519 public key for verification
	reconnectDelay    time.Duration
	maxReconnectDelay time.Duration

	mu     sync.Mutex
	closed bool
}

// SSEWatcherOption configures an SSEWatcher.
type SSEWatcherOption func(*SSEWatcher)

// WithPublicKey sets the Ed25519 public key for bundle signature verification.
func WithPublicKey(hex string) SSEWatcherOption {
	return func(w *SSEWatcher) { w.publicKeyHex = hex }
}

// WithReconnectDelay sets the initial reconnect delay.
func WithReconnectDelay(d time.Duration) SSEWatcherOption {
	return func(w *SSEWatcher) { w.reconnectDelay = d }
}

// WithMaxReconnectDelay sets the maximum reconnect delay.
func WithMaxReconnectDelay(d time.Duration) SSEWatcherOption {
	return func(w *SSEWatcher) { w.maxReconnectDelay = d }
}

// NewSSEWatcher creates a watcher that listens for contract updates via SSE.
func NewSSEWatcher(client *Client, reloader Reloader, opts ...SSEWatcherOption) *SSEWatcher {
	w := &SSEWatcher{
		client:            client,
		reloader:          reloader,
		reconnectDelay:    1 * time.Second,
		maxReconnectDelay: 60 * time.Second,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Watch blocks and listens for SSE events. Reconnects on disconnect.
// Returns when the context is cancelled or Close is called.
func (w *SSEWatcher) Watch(ctx context.Context) error {
	delay := w.reconnectDelay
	consecutiveFailures := 0
	var connectedAt time.Time

	for {
		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		if closed {
			return nil
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		connectedAt = time.Now()
		err := w.connectAndListen(ctx)
		if err == nil {
			// Clean disconnect -- reset backoff.
			delay = w.reconnectDelay
			consecutiveFailures = 0
			continue
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.mu.Lock()
		closed = w.closed
		w.mu.Unlock()
		if closed {
			return nil
		}

		// If connection was stable (>30s), reset backoff.
		if !connectedAt.IsZero() && time.Since(connectedAt) >= 30*time.Second {
			delay = w.reconnectDelay
			consecutiveFailures = 0
		}

		consecutiveFailures++
		if consecutiveFailures <= 3 {
			log.Printf("server: SSE connection lost (%v), reconnecting in %v", err, delay)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay = time.Duration(math.Min(
			float64(delay)*2,
			float64(w.maxReconnectDelay),
		))
	}
}

func (w *SSEWatcher) connectAndListen(ctx context.Context) error {
	sseURL := w.client.baseURL + "/api/v1/stream?env=" + neturl.QueryEscape(w.client.env)
	if w.client.bundleName != "" {
		sseURL += "&bundle_name=" + neturl.QueryEscape(w.client.bundleName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return fmt.Errorf("build SSE request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.client.apiKey)
	req.Header.Set("Accept", "text/event-stream")

	// Use a client without timeout for long-lived SSE connections.
	sseHTTP := &http.Client{}
	resp, err := sseHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connect: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE unexpected status: %d", resp.StatusCode)
	}

	return w.readEvents(ctx, resp)
}

func (w *SSEWatcher) readEvents(ctx context.Context, resp *http.Response) error {
	scanner := bufio.NewScanner(resp.Body)
	// Contract bundles can be up to MaxBundleSize (1 MB). SSE data lines
	// carry the full JSON-encoded bundle, so the scanner buffer must be
	// large enough to hold at least that plus SSE framing overhead.
	const sseBufSize = 1_100_000 // ~1 MB + overhead for SSE framing
	scanner.Buffer(make([]byte, 0, sseBufSize), sseBufSize)
	var eventType, data string

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		if closed {
			return nil
		}

		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "":
			// Empty line = end of event.
			if eventType == "contract_update" && data != "" {
				w.handleContractUpdate(data)
			}
			eventType = ""
			data = ""
		}
	}
	return scanner.Err()
}

func (w *SSEWatcher) handleContractUpdate(data string) {
	var bundle map[string]any
	if err := json.Unmarshal([]byte(data), &bundle); err != nil {
		log.Printf("server: invalid JSON in SSE contract_update event: %v", err)
		return
	}

	yamlStr, _ := bundle["yaml"].(string)
	if yamlStr == "" {
		log.Printf("server: SSE contract_update missing 'yaml' field")
		return
	}

	yamlBytes := []byte(yamlStr)

	// Verify signature if public key is configured.
	if w.publicKeyHex != "" {
		sigB64, _ := bundle["signature"].(string)
		if err := VerifyBundleSignature(yamlBytes, sigB64, w.publicKeyHex); err != nil {
			log.Printf("server: bundle verification failed: %v", err)
			return
		}
	}

	if err := w.reloader.ReloadFromYAML(yamlBytes); err != nil {
		log.Printf("server: failed to reload contracts: %v", err)
	}
}

// Close stops the watcher.
func (w *SSEWatcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}
