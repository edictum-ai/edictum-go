# Anthropic SDK Go Adapter

Wrap Anthropic SDK Go tool functions with Edictum rules and workflow state.

Import path:

```go
import "github.com/edictum-ai/edictum-go/adapter/anthropic"
```

API:

```go
func New(g *guard.Guard, opts ...guard.RunOption) *Adapter

func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, input json.RawMessage) (any, error),
) func(ctx context.Context, input json.RawMessage) (any, error)
```

Behavior notes:

- The adapter unmarshals `json.RawMessage` into `map[string]any` for rule evaluation.
- The wrapped function still receives the original raw payload.

Example:

```go
package main

import (
	"context"
	"encoding/json"

	"github.com/edictum-ai/edictum-go/adapter/anthropic"
	"github.com/edictum-ai/edictum-go/guard"
)

func main() {
	g, _ := guard.FromYAML("rules.yaml")

	adapter := anthropic.New(g, guard.WithSessionID("hero-session"))
	tool := adapter.WrapTool("Write", func(ctx context.Context, input json.RawMessage) (any, error) {
		return map[string]any{"ok": true}, nil
	})

	_, _ = tool(context.Background(), json.RawMessage(`{"path":"notes.md","content":"hello"}`))
}
```
