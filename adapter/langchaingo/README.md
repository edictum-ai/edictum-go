# LangChainGo Adapter

Wrap LangChainGo tool functions with Edictum rules and workflow state.

Import path:

```go
import "github.com/edictum-ai/edictum-go/adapter/langchaingo"
```

API:

```go
func New(g *guard.Guard, opts ...guard.RunOption) *Adapter

func (a *Adapter) WrapTool(
	toolName string,
	fn func(ctx context.Context, input string) (string, error),
) func(ctx context.Context, input string) (string, error)
```

Behavior notes:

- JSON string input is parsed into `map[string]any` before evaluation.
- Non-JSON input falls back to `map[string]any{"input": rawString}`.

Example:

```go
package main

import (
	"context"

	"github.com/edictum-ai/edictum-go/adapter/langchaingo"
	"github.com/edictum-ai/edictum-go/guard"
)

func main() {
	g, _ := guard.FromYAML("rules.yaml")

	adapter := langchaingo.New(g, guard.WithSessionID("hero-session"))
	tool := adapter.WrapTool("Search", func(ctx context.Context, input string) (string, error) {
		return "ok", nil
	})

	_, _ = tool(context.Background(), `{"query":"workflow gates"}`)
}
```
