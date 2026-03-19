package guard

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/edictum-ai/edictum-go/server"
	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
)

// FromServer creates a Guard connected to an edictum-console server.
// The server provides contracts via HTTP, with optional SSE hot-reload.
//
// Required: url, apiKey, agentID, and WithBundleName (via opts).
// Use WithVerifySignatures, WithAutoWatch, WithAllowInsecure, WithTags
// for server-specific configuration. Standard Guard options (WithMode,
// WithEnvironment, etc.) are also accepted and override server defaults.
func FromServer(url, apiKey, agentID string, opts ...Option) (*Guard, error) {
	fc, environment := extractFactoryAndEnv(opts)

	if fc.bundleName == "" {
		return nil, fmt.Errorf(
			"FromServer: WithBundleName is required; " +
				"server-assigned mode (empty bundle name) is not yet supported in Go")
	}
	if fc.verifySignatures && fc.signingPublicKey == "" {
		return nil, fmt.Errorf(
			"FromServer: signing public key is required when verify_signatures is true")
	}

	client, err := server.NewClient(server.ClientConfig{
		BaseURL:       url,
		APIKey:        apiKey,
		AgentID:       agentID,
		Env:           environment,
		BundleName:    fc.bundleName,
		Tags:          fc.tags,
		AllowInsecure: fc.allowInsecure,
	})
	if err != nil {
		return nil, fmt.Errorf("FromServer: %w", err)
	}

	serverAudit := server.NewAuditSink(client)
	serverBackend := server.NewBackend(client)
	serverApproval := server.NewApprovalBackend(client)

	// Fetch the current bundle from the server.
	ctx := context.Background()
	resp, err := client.Get(ctx, fmt.Sprintf("/api/v1/bundles/%s/current", fc.bundleName))
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: failed to fetch contracts: %w", err)
	}
	if resp == nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: bundle %q not found on server", fc.bundleName)
	}

	// Decode the YAML from the server response.
	yamlB64, _ := resp["yaml_bytes"].(string)
	bundleYAML, err := base64.StdEncoding.DecodeString(yamlB64)
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: invalid base64 in yaml_bytes: %w", err)
	}

	// Optional signature verification.
	if fc.verifySignatures {
		sigB64, _ := resp["signature"].(string)
		if sigB64 == "" {
			serverAudit.Close(ctx)
			return nil, fmt.Errorf(
				"FromServer: server response missing signature but verify_signatures is true")
		}
		if verifyErr := server.VerifyBundleSignature(bundleYAML, sigB64, fc.signingPublicKey); verifyErr != nil {
			serverAudit.Close(ctx)
			return nil, fmt.Errorf("FromServer: %w", verifyErr)
		}
	}

	// Parse and compile the bundle.
	data, hash, err := yamlpkg.LoadBundleString(string(bundleYAML))
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: %w", err)
	}
	compiled, err := yamlpkg.Compile(data)
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: %w", err)
	}

	// Build option list: server defaults → compiled → user (user wins).
	serverDefaults := []Option{
		WithAuditSink(serverAudit),
		WithBackend(serverBackend),
		WithApprovalBackend(serverApproval),
	}
	compiledDefaults := compiledOpts(compiled, hash.String())

	allOpts := make([]Option, 0, len(serverDefaults)+len(compiledDefaults)+len(opts))
	allOpts = append(allOpts, serverDefaults...)
	allOpts = append(allOpts, compiledDefaults...)
	allOpts = append(allOpts, opts...)

	g := New(allOpts...)
	g.serverClient = client

	// Start SSE watcher for hot-reload if enabled.
	if fc.autoWatch {
		var watcherOpts []server.SSEWatcherOption
		if fc.signingPublicKey != "" {
			watcherOpts = append(watcherOpts, server.WithPublicKey(fc.signingPublicKey))
		}
		watcher := server.NewSSEWatcher(client, g, watcherOpts...)
		g.sseCloser = watcher
		go watcher.Watch(context.Background()) //nolint:errcheck // background watcher logs errors
	}

	return g, nil
}

// Close stops the SSE watcher and flushes audit events.
// Safe to call on guards not created by FromServer (no-op).
// Safe to call multiple times.
func (g *Guard) Close(ctx context.Context) {
	if g.sseCloser != nil {
		g.sseCloser.Close()
	}
	type flusher interface {
		Close(context.Context)
	}
	if f, ok := g.auditSink.(flusher); ok {
		f.Close(ctx)
	}
}
