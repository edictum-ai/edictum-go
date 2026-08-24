# Edictum

Edictum is the agency control layer for production AI agents in Go.

Agent frameworks build the agent. Edictum bounds the agency.

Rulesets and Workflow Gates turn declared agent profiles into executable
runtime boundaries: rules block unsafe tool calls, and Workflow Gates enforce
ordered process with evidence and approvals.

Edictum makes any agency level defensible. Medium Agency is the enterprise
demand center right now, but the same runtime enforcement applies to lower- and
higher-agency profiles.

[![Go Reference](https://pkg.go.dev/badge/github.com/edictum-ai/edictum-go.svg)](https://pkg.go.dev/github.com/edictum-ai/edictum-go)
[![CI](https://github.com/edictum-ai/edictum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/edictum-ai/edictum-go/actions/workflows/ci.yml)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-blue)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Prompts are suggestions -- agency boundaries are enforcement.**
The LLM cannot talk its way past a rule or workflow gate.

**Zero runtime deps** | **Fail-closed by default** | **660+ tests, -race clean**

## What it does

- **Deterministic YAML rules** that execute outside the model -- no prompt-level bypass possible
- **Workflow Gates** that enforce ordered process, required evidence, and approvals before execution
- **Immune to prompt injection** -- rules are not part of the prompt, they run in a separate pipeline
- **Fail-closed by default** -- if evaluation errors, the tool call is blocked
- **Behavioral conformance measurement** to a declared profile; Edictum does not replace output-quality evals for accuracy, relevance, coherence, or answer quality

## Install

```bash
go get github.com/edictum-ai/edictum-go
```

Requires Go 1.25+.

## Quick start

Rulesets are one part of agency control. Use them to express deterministic
tool-call boundaries for the declared agent profile.

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

## Workflow Gates and CLI Gate

Gate bounds coding-assistant agency before tool execution. It enforces rules and
optional workflow state before the runner executes the call.

Rulesets answer whether a tool call fits the declared profile. Workflow Gates
add ordered process: read context before writing, verify before push, require
approval before protected operations, and emit audit events for each decision.

For read/write agents, Edictum can require read-before-write evidence,
verification before push, approval before protected operations, and audit events
for every decision.

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

Example workflow:

```yaml
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: read-write-agent
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: "Read the spec first"
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
  - id: verify
    entry:
      - condition: stage_complete("implement")
    tools: [Bash]
    checks:
      - command_matches: '^go test ./\.\.\.$'
        message: "Run verification before pushing"
  - id: approve-push
    entry:
      - condition: stage_complete("verify")
    approval:
      message: "Approval required before push"
  - id: push
    entry:
      - condition: stage_complete("approve-push")
    tools: [Bash]
    checks:
      - command_matches: '^git push\b'
        message: "Only push after verification and approval"
```

Run actual tool execution through the full runtime with a stable session ID:

```bash
echo '{"tool_name":"Read","tool_input":{"path":"spec.md"}}' \
  | edictum gate run --format raw --session-id mimi-task-42 -- ./openclaw-tool-runner
```

For coding-assistant demos:

- keep ruleset YAML and workflow YAML as separate files
- reuse the same `--session-id` across one agent task so workflow state advances
- route real tool execution through `gate run`; `gate check` evaluates rules only

For embedded consumers, the workflow runtime exposes explicit stage-control and
state APIs:

```go
package main

import (
    "context"
    "fmt"

    "github.com/edictum-ai/edictum-go/session"
    "github.com/edictum-ai/edictum-go/workflow"
)

func main() {
    ctx := context.Background()
    backend := session.NewMemoryBackend()

    definition, err := workflow.Load("coding-guard.yaml")
    if err != nil {
        panic(err)
    }

    runtime, err := workflow.NewRuntime(definition)
    if err != nil {
        panic(err)
    }

    sess, err := session.New("hero-session", backend)
    if err != nil {
        panic(err)
    }

    events, err := runtime.SetStage(ctx, sess, "review")
    if err != nil {
        panic(err)
    }
    _ = events // emits workflow_state_updated audit payloads

    state, err := runtime.State(ctx, sess)
    if err != nil {
        panic(err)
    }

    fmt.Println(definition.Metadata.Version)
    fmt.Println(state.ActiveStage)
    fmt.Println(state.BlockedReason)
    fmt.Println(state.PendingApproval.Required)
}
```

Audit events emitted from runtime runs include `session_id`, `parent_session_id`,
and workflow progress actions such as `workflow_state_updated`.

## Adapters

All adapters use `New(g, opts...)` + `WrapTool()`. Zero external framework dependencies.
Adapter-level `guard.RunOption` values become default run metadata for wrapped
calls, which lets external consumers pin session IDs, lineage, environment, or
principal data without a local fork.

| Framework | Import |
|-----------|--------|
| Google ADK Go | `github.com/edictum-ai/edictum-go/adapter/adkgo` |
| Anthropic SDK Go | `github.com/edictum-ai/edictum-go/adapter/anthropic` |
| Eino / CloudWeGo | `github.com/edictum-ai/edictum-go/adapter/eino` |
| Firebase Genkit | `github.com/edictum-ai/edictum-go/adapter/genkit` |
| LangChainGo | `github.com/edictum-ai/edictum-go/adapter/langchaingo` |

```go
import "github.com/edictum-ai/edictum-go/adapter/adkgo"

adapter := adkgo.New(
    g,
    guard.WithSessionID("hero-session"),
    guard.WithRunEnvironment("hero-demo"),
)
wrappedTool := adapter.WrapTool("Bash", originalToolFunc)
```

## Feature parity

Full parity with [edictum](https://github.com/edictum-ai/edictum) Python reference -- 660+ tests, all passing with `-race`.

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
| edictum-api | Control Plane API | [github.com/edictum-ai/edictum-api](https://github.com/edictum-ai/edictum-api) |
| edictum-app | Control Plane UI | [github.com/edictum-ai/edictum-app](https://github.com/edictum-ai/edictum-app) |
| edictum-schemas | Ruleset schemas | [github.com/edictum-ai/edictum-schemas](https://github.com/edictum-ai/edictum-schemas) |
| edictum-demo | Demos & benchmarks | [github.com/edictum-ai/edictum-demo](https://github.com/edictum-ai/edictum-demo) |

## Docs

[docs.edictum.ai](https://docs.edictum.ai)

## License

MIT -- see [LICENSE](LICENSE).
