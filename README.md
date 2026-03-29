# Edictum

Go SDK for runtime rule enforcement on AI agent tool calls.

[![Go Reference](https://pkg.go.dev/badge/github.com/edictum-ai/edictum-go.svg)](https://pkg.go.dev/github.com/edictum-ai/edictum-go)
[![CI](https://github.com/edictum-ai/edictum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/edictum-ai/edictum-go/actions/workflows/ci.yml)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-blue)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Prompts are suggestions -- rules are enforcement.**
The LLM cannot talk its way past a rule.

**Zero runtime deps** | **Fail-closed by default** | **485 tests, -race clean**

## What it does

- **Deterministic YAML rules** that execute outside the model -- no prompt-level bypass possible
- **Immune to prompt injection** -- rules are not part of the prompt, they run in a separate pipeline
- **Fail-closed by default** -- if evaluation errors, the tool call is blocked

## Install

```bash
go get github.com/edictum-ai/edictum-go
```

Requires Go 1.25+.

## Quick start

Define a ruleset in YAML:

```yaml
apiVersion: edictum/v1
kind: Ruleset
defaults:
  mode: enforce
rules:
  - id: no-destructive-bash
    type: pre
    tool: Bash
    when:
      args.command:
        contains_any: ["rm -rf", "DROP TABLE", "FORMAT"]
    then:
      action: block
      message: "Destructive command blocked: {args.command}"
```

Load and enforce:

```go
package main

import (
    "context"
    "errors"
    "fmt"

    edictum "github.com/edictum-ai/edictum-go"
    "github.com/edictum-ai/edictum-go/guard"
)

func main() {
    g, err := guard.FromYAML("rules.yaml")
    if err != nil {
        panic(err)
    }

    myTool := func(args map[string]any) (any, error) {
        // your tool implementation
        return nil, nil
    }

    result, err := g.Run(context.Background(), "Bash",
        map[string]any{"command": "rm -rf /"}, myTool)

    var blocked *edictum.BlockedError
    if errors.As(err, &blocked) {
        fmt.Println("Blocked:", blocked.Reason)
        return
    }
    fmt.Println("Result:", result)
}
```

## Gate Workflow Runtime

`edictum gate check` remains a preflight hook path in M1. It evaluates rules only.
Workflow Gates are enforced by the real execution path: `edictum gate run`.

Initialize Gate with separate rules and workflow documents:

```bash
edictum gate init \
  --rules ./policy/rules \
  --workflow ./policy/workflow.yaml
```

If the workflow uses trusted `exec(...)` conditions, opt in explicitly:

```bash
edictum gate init \
  --rules ./policy/rules \
  --workflow ./policy/workflow.yaml \
  --workflow-exec
```

Run actual tool execution through the full runtime with a stable session ID:

```bash
echo '{"tool_name":"Read","tool_input":{"path":"spec.md"}}' \
  | edictum gate run --format raw --session-id mimi-task-42 -- ./openclaw-tool-runner
```

For M1 dogfood:

- keep ruleset YAML and workflow YAML as separate files
- reuse the same `--session-id` across one agent task so workflow state advances
- route real tool execution through `gate run`; `gate check` will not enforce workflows

## Adapters

All adapters use `New(g)` + `WrapTool()`. Zero external framework dependencies.

| Framework | Import |
|-----------|--------|
| Google ADK Go | `github.com/edictum-ai/edictum-go/adapter/adkgo` |
| Anthropic SDK Go | `github.com/edictum-ai/edictum-go/adapter/anthropic` |
| Eino / CloudWeGo | `github.com/edictum-ai/edictum-go/adapter/eino` |
| Firebase Genkit | `github.com/edictum-ai/edictum-go/adapter/genkit` |
| LangChainGo | `github.com/edictum-ai/edictum-go/adapter/langchaingo` |

```go
import "github.com/edictum-ai/edictum-go/adapter/adkgo"

adapter := adkgo.New(g)
wrappedTool := adapter.WrapTool("Bash", originalToolFunc)
```

## Feature parity

Full parity with [edictum](https://github.com/edictum-ai/edictum) Python reference -- 485 tests, all passing with `-race`.

## Security

This is a security product. See [SECURITY.md](SECURITY.md) for the vulnerability reporting process.

Every security boundary has bypass tests. Every error path fails closed. Every shared state is mutex-protected.

## Research

- [arXiv:2503.07918](https://arxiv.org/abs/2503.07918) -- *Runtime Rule Enforcement for AI Agent Tool Calls*
- [OpenClaw](https://openclaw.org) -- Open dataset of 650+ real-world tool-call failures that motivated Edictum's rule model

## Ecosystem

| Repo | Role | Link |
|------|------|------|
| edictum | Python SDK (reference) | [github.com/edictum-ai/edictum](https://github.com/edictum-ai/edictum) |
| edictum-go | Go SDK | [github.com/edictum-ai/edictum-go](https://github.com/edictum-ai/edictum-go) |
| edictum-ts | TypeScript SDK | [github.com/edictum-ai/edictum-ts](https://github.com/edictum-ai/edictum-ts) |
| edictum-console | Ops Console | [github.com/edictum-ai/edictum-console](https://github.com/edictum-ai/edictum-console) |
| edictum-schemas | Ruleset schemas | [github.com/edictum-ai/edictum-schemas](https://github.com/edictum-ai/edictum-schemas) |
| edictum-demo | Demos & benchmarks | [github.com/edictum-ai/edictum-demo](https://github.com/edictum-ai/edictum-demo) |

## Docs

[docs.edictum.ai](https://docs.edictum.ai)

## License

MIT -- see [LICENSE](LICENSE).
