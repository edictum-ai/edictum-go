package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/edictum-ai/edictum-go/server"
	yamlpkg "github.com/edictum-ai/edictum-go/yaml"
)

// assignmentTimeout is how long FromServer waits for the server to push
// a bundle in server-assigned mode (empty bundle name).
const assignmentTimeout = 30 * time.Second

// FromServer creates a Guard connected to an edictum-console server.
// The server provides rules via HTTP, with optional SSE hot-reload.
//
// When WithBundleName is set, the named bundle is fetched immediately.
// When WithBundleName is omitted (server-assigned mode), FromServer
// starts the SSE watcher and waits up to 30 seconds for the server to
// assign a bundle via an _assignment_changed event.
//
// Use WithVerifySignatures, WithAutoWatch, WithAllowInsecure, WithTags
// for server-specific configuration. Standard Guard options (WithMode,
// WithEnvironment, etc.) are also accepted and override server defaults.
func FromServer(url, apiKey, agentID string, opts ...Option) (*Guard, error) {
	fc, environment := extractFactoryAndEnv(opts)

	if fc.bundleName == "" && !fc.autoWatch {
		return nil, fmt.Errorf(
			"FromServer: auto_watch must be true when bundle_name is empty; " +
				"server-assigned mode requires the SSE connection to receive the bundle")
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

	serverDefaults := []Option{
		WithAuditSink(serverAudit),
		WithBackend(serverBackend),
		WithApprovalBackend(serverApproval),
	}

	if fc.bundleName != "" {
		return fromServerWithBundle(fc, client, serverAudit, serverDefaults, opts)
	}
	return fromServerAssigned(fc, client, serverDefaults, opts)
}

// fromServerWithBundle handles the case where a bundle name is known.
func fromServerWithBundle(
	fc *factoryCfg,
	client *server.Client,
	serverAudit *server.AuditSink,
	serverDefaults, userOpts []Option,
) (*Guard, error) {
	ctx := context.Background()
	resp, err := client.Get(ctx, fmt.Sprintf("/api/v1/bundles/%s/current", fc.bundleName))
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: failed to fetch rules: %w", err)
	}
	if resp == nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: bundle %q not found on server", fc.bundleName)
	}

	bundleYAML, err := decodeYAMLResponse(resp)
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: %w", err)
	}

	if err := verifyIfNeeded(fc, resp, bundleYAML); err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: %w", err)
	}

	data, hash, err := yamlpkg.LoadBundleString(string(bundleYAML))
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: %w", err)
	}
	compOpts := buildCompileOpts(fc)
	compiled, err := yamlpkg.Compile(data, compOpts...)
	if err != nil {
		serverAudit.Close(ctx)
		return nil, fmt.Errorf("FromServer: %w", err)
	}

	compiledDefaults := compiledOpts(compiled, hash.String())
	allOpts := make([]Option, 0, 1+len(serverDefaults)+len(compiledDefaults)+len(userOpts))
	allOpts = append(allOpts, suppressFactoryWarnings())
	allOpts = append(allOpts, serverDefaults...)
	allOpts = append(allOpts, compiledDefaults...)
	allOpts = append(allOpts, userOpts...)

	g := New(allOpts...)
	g.compileOpts = compOpts
	g.serverClient = client
	if fc.autoWatch {
		startWatcher(g, client, fc)
	}
	return g, nil
}

// fromServerAssigned handles server-assigned mode: starts the SSE watcher
// and waits for the server to push the first bundle assignment.
func fromServerAssigned(
	fc *factoryCfg,
	client *server.Client,
	serverDefaults, userOpts []Option,
) (*Guard, error) {
	allOpts := make([]Option, 0, 1+len(serverDefaults)+len(userOpts))
	allOpts = append(allOpts, suppressFactoryWarnings())
	allOpts = append(allOpts, serverDefaults...)
	allOpts = append(allOpts, userOpts...)

	g := New(allOpts...)
	g.compileOpts = buildCompileOpts(fc)
	g.serverClient = client

	readyCh := make(chan struct{})
	nr := &notifyingReloader{inner: g, readyCh: readyCh}

	var watcherOpts []server.SSEWatcherOption
	if fc.signingPublicKey != "" {
		watcherOpts = append(watcherOpts, server.WithPublicKey(fc.signingPublicKey))
	}
	watcher := server.NewSSEWatcher(client, nr, watcherOpts...)
	watchCtx, watchCancel := context.WithCancel(context.Background())

	g.mu.Lock()
	g.sseCloser = watcher
	g.watchCancel = watchCancel
	g.mu.Unlock()

	go watcher.Watch(watchCtx) //nolint:errcheck // background watcher logs errors

	select {
	case <-readyCh:
		return g, nil
	case <-time.After(assignmentTimeout):
		g.Close(context.Background())
		return nil, fmt.Errorf(
			"FromServer: server did not push a bundle assignment within %v; "+
				"check that the server has an assignment rule matching this agent's tags",
			assignmentTimeout)
	}
}
