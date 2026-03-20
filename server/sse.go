package server

import (
	"bufio"
	"context"
	"encoding/base64"
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
//
// Handles two event types:
//   - Regular contract_update: YAML is in the event data (raw "yaml" or
//     base64 "yaml_bytes"). Calls ReloadFromYAML directly.
//   - Assignment change: event has "_assignment_changed" and "bundle_name".
//     Fetches the full bundle from the server, then calls ReloadFromYAML.
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
	streamPath := "/api/v1/stream?env=" + neturl.QueryEscape(w.client.Env())
	if bn := w.client.BundleName(); bn != "" {
		streamPath += "&bundle_name=" + neturl.QueryEscape(bn)
	}

	// Use Client.buildRequest for auth headers, then override Accept.
	req, err := w.client.buildRequest(ctx, http.MethodGet, streamPath, nil)
	if err != nil {
		return fmt.Errorf("build SSE request: %w", err)
	}
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
			// Per RFC 8895 §9.2.6, multiple data: lines are joined with \n.
			chunk := strings.TrimPrefix(line, "data: ")
			if data == "" {
				data = chunk
			} else {
				data = data + "\n" + chunk
			}
		case line == "":
			// Empty line = end of event.
			if eventType == "contract_update" && data != "" {
				w.handleContractUpdate(ctx, data)
			}
			eventType = ""
			data = ""
		}
	}
	return scanner.Err()
}

// handleContractUpdate processes a contract_update SSE event.
// Two sub-types:
//   - Assignment change: has "_assignment_changed" + "bundle_name".
//     Fetches the full bundle from the server and reloads.
//   - Regular update: has "yaml" (raw) or "yaml_bytes" (base64).
//     Decodes and reloads directly.
func (w *SSEWatcher) handleContractUpdate(ctx context.Context, data string) {
	var bundle map[string]any
	if err := json.Unmarshal([]byte(data), &bundle); err != nil {
		log.Printf("server: invalid JSON in SSE contract_update event: %v", err)
		return
	}

	if isAssignment, _ := bundle["_assignment_changed"].(bool); isAssignment {
		w.handleAssignmentChange(ctx, bundle)
		return
	}

	yamlBytes, sigB64 := extractYAML(bundle)
	if yamlBytes == nil {
		log.Printf("server: SSE contract_update missing 'yaml' or 'yaml_bytes' field")
		return
	}

	if !w.verifySignature(yamlBytes, sigB64) {
		return
	}

	if err := w.reloader.ReloadFromYAML(yamlBytes); err != nil {
		log.Printf("server: failed to reload contracts: %v", err)
	}
}

// handleAssignmentChange processes an _assignment_changed event.
// Fetches the full bundle from the server, reloads, and updates the
// client's bundle name.
func (w *SSEWatcher) handleAssignmentChange(ctx context.Context, bundle map[string]any) {
	newName, _ := bundle["bundle_name"].(string)
	if newName == "" {
		log.Printf("server: SSE assignment event missing 'bundle_name'")
		return
	}
	// Validate before interpolating into URL path — an attacker controlling
	// the SSE stream could inject path traversal (../../) or query params.
	if err := validateIdentifier("bundle_name", newName); err != nil {
		log.Printf("server: SSE assignment event rejected: %v", err)
		return
	}

	resp, err := w.client.Get(ctx, fmt.Sprintf("/api/v1/bundles/%s/current", newName))
	if err != nil {
		log.Printf("server: failed to fetch assigned bundle %q: %v", newName, err)
		return
	}
	if resp == nil {
		log.Printf("server: assigned bundle %q not found on server (404)", newName)
		return
	}

	yamlBytes, sigB64 := extractYAMLFromResponse(resp)
	if yamlBytes == nil {
		log.Printf("server: assigned bundle %q response missing yaml_bytes", newName)
		return
	}

	if !w.verifySignature(yamlBytes, sigB64) {
		return
	}

	if err := w.reloader.ReloadFromYAML(yamlBytes); err != nil {
		log.Printf("server: failed to reload assigned bundle %q: %v", newName, err)
		return
	}

	w.client.SetBundleName(newName)
}

// extractYAML extracts YAML bytes from an SSE event payload.
// Tries "yaml_bytes" (base64) first, then "yaml" (raw string).
func extractYAML(bundle map[string]any) (yamlBytes []byte, sigB64 string) {
	sigB64, _ = bundle["signature"].(string)

	if b64, ok := bundle["yaml_bytes"].(string); ok && b64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Printf("server: invalid base64 in SSE yaml_bytes: %v", err)
			return nil, ""
		}
		return decoded, sigB64
	}

	if raw, ok := bundle["yaml"].(string); ok && raw != "" {
		return []byte(raw), sigB64
	}

	return nil, ""
}

// extractYAMLFromResponse extracts YAML bytes from a server HTTP response
// (e.g., /api/v1/bundles/{name}/current). Uses "yaml_bytes" (base64).
func extractYAMLFromResponse(resp map[string]any) (yamlBytes []byte, sigB64 string) {
	sigB64, _ = resp["signature"].(string)

	b64, _ := resp["yaml_bytes"].(string)
	if b64 == "" {
		return nil, ""
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Printf("server: invalid base64 in response yaml_bytes: %v", err)
		return nil, ""
	}
	return decoded, sigB64
}

// verifySignature checks the bundle signature if a public key is configured.
// Returns true if verification passes or no key is configured.
func (w *SSEWatcher) verifySignature(yamlBytes []byte, sigB64 string) bool {
	if w.publicKeyHex == "" {
		return true
	}
	if err := VerifyBundleSignature(yamlBytes, sigB64, w.publicKeyHex); err != nil {
		log.Printf("server: bundle verification failed: %v", err)
		return false
	}
	return true
}

// Close signals the watcher to stop. For immediate shutdown, also cancel
// the context passed to Watch(). Close without context cancellation waits
// for the current SSE connection to disconnect naturally.
func (w *SSEWatcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}
