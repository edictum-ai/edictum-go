package guard

import "context"

type runContextKey struct{}

// ContextWithRunOptions returns a context that carries guard.Run options.
// Adapters use the call context as their only side channel, so this lets
// wrapped tool calls set run-scoped lineage without changing adapter APIs.
func ContextWithRunOptions(ctx context.Context, opts ...RunOption) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, _ := ctx.Value(runContextKey{}).(runConfig)
	for _, opt := range opts {
		opt(&cfg)
	}
	return context.WithValue(ctx, runContextKey{}, cfg)
}

func applyContextRunOptions(ctx context.Context, cfg *runConfig) {
	if ctx == nil || cfg == nil {
		return
	}
	contextCfg, _ := ctx.Value(runContextKey{}).(runConfig)
	if contextCfg.sessionID != "" {
		cfg.sessionID = contextCfg.sessionID
	}
	if contextCfg.parentSessionID != "" {
		cfg.parentSessionID = contextCfg.parentSessionID
	}
	if contextCfg.environment != "" {
		cfg.environment = contextCfg.environment
	}
	if contextCfg.principal != nil {
		cfg.principal = contextCfg.principal
	}
}
