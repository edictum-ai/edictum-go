# ADK Go Adapter

Wrap Google ADK Go tool functions with Edictum rules and workflow state.

Import path:

```go
import "github.com/edictum-ai/edictum-go/adapter/adkgo"
```

API:

```go
func New(g *guard.Guard, opts ...guard.RunOption) *Adapter

func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, args map[string]any) (any, error),
) func(ctx context.Context, args map[string]any) (any, error)
```

Example:

```go
package main

import (
	"context"

	"github.com/edictum-ai/edictum-go/adapter/adkgo"
	"github.com/edictum-ai/edictum-go/guard"
)

func main() {
	g, _ := guard.FromYAML("rules.yaml")

	adapter := adkgo.New(g, guard.WithSessionID("hero-session"))
	tool := adapter.WrapTool("Bash", func(ctx context.Context, args map[string]any) (any, error) {
		return "ok", nil
	})

	_, _ = tool(context.Background(), map[string]any{"command": "git diff"})
}
```

Any `guard.RunOption` values passed to `New()` become default metadata for wrapped calls.
