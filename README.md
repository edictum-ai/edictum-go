# Edictum Go

[![Go Reference](https://pkg.go.dev/badge/github.com/edictum-ai/edictum-go.svg)](https://pkg.go.dev/github.com/edictum-ai/edictum-go)
[![CI](https://github.com/edictum-ai/edictum-go/actions/workflows/ci.yml/badge.svg)](https://github.com/edictum-ai/edictum-go/actions/workflows/ci.yml)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-blue)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Go SDK for Edictum, the developer agent behavior platform. Tell your agents what to do, and make sure they do it.

Workflow Gates shipped here first. `edictum gate` intercepts real coding-assistant tool calls, keeps state across a task, and blocks steps that skip your process.

**Version:** `v0.4.0`  
**Core:** zero runtime deps  
**Adapters:** ADK Go, LangChainGo, Anthropic SDK Go, Eino, Genkit

## The Problem

Agents can say the right thing in chat and still call the wrong tool.

The GAP paper measured 17,420 datapoints across 6 frontier models and found a 55-79% gap between text refusal and tool-call behavior. Prompt instructions are advisory. Tool execution is what matters.

Edictum sits on the tool-call path:

- Rulesets decide whether a tool call is allowed.
- Workflow Gates decide whether the agent is at the right step yet.
- Both run outside the model.

Think ESLint for agent behavior. Think OPA for tool calls.

## Quick Start

Install the SDK:

```bash
go get github.com/edictum-ai/edictum-go
```

Write `rules.yaml`:

```yaml
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: local-dev-rules
defaults:
  mode: enforce
rules:
  - id: block-destructive-bash
    type: pre
    tool: Bash
    when:
      args.command:
        contains_any:
          - "rm -rf"
          - "git push origin main"
          - "DROP TABLE"
    then:
      action: block
      message: "Blocked dangerous command: {args.command}"
```

Load the ruleset and run the tool call through the guard:

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

	result, err := g.Run(
		context.Background(),
		"Bash",
		map[string]any{"command": "go test ./..."},
		func(args map[string]any) (any, error) {
			return "tests passed", nil
		},
	)
	if err != nil {
		var blocked *edictum.BlockedError
		if errors.As(err, &blocked) {
			fmt.Println("blocked:", blocked.Reason)
			return
		}
		panic(err)
	}

	fmt.Println(result)
}
```

`guard.Run()` is the full path: pre-checks, approvals, tool execution, post-checks, redaction, session state, and decision-log emission.

## Workflow Gates

Use Workflow Gates when you need process, not just point-in-time rules.

`edictum gate check` is a hook-style preflight. It evaluates rules only.

`edictum gate run` is the real execution path. It runs the tool, persists session state, advances workflow stages, and handles approvals.

Install the CLI:

```bash
go install github.com/edictum-ai/edictum-go/cmd/edictum@v0.4.0
```

Write a workflow with the real runtime format:

```yaml
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: ship-feature
  description: "Read the spec, implement, review, verify"
  version: "1.0"
stages:
  - id: read-context
    description: "Read the spec before touching code"
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: "Read the spec first"

  - id: implement
    description: "Make the code change"
    tools: [Edit, Write]
    entry:
      - condition: stage_complete("read-context")
    checks:
      - command_matches: "git diff"
        message: "Run git diff before you leave implement"
      - command_not_matches: "git push.*main"
        message: "Never push straight to main"

  - id: review
    description: "Ask for human review"
    entry:
      - condition: stage_complete("implement")
    approval:
      message: "Review required before verification"

  - id: verify
    description: "Run the verification step"
    tools: [Bash]
    entry:
      - condition: stage_complete("review")
    exit:
      - condition: exec("go test ./...", exit_code=0)
        message: "Tests must pass"
```

Initialize Gate with rules and workflow files:

```bash
edictum gate init \
  --rules ./policy/rules \
  --workflow ./policy/workflow.yaml \
  --workflow-exec
```

Run real tool calls through the workflow with a stable session ID:

```bash
echo '{"tool_name":"Read","tool_input":{"path":"spec.md"}}' \
  | edictum gate run --format raw --session-id feature-42 -- ./tool-runner

echo '{"tool_name":"Edit","tool_input":{"path":"internal/app.go"}}' \
  | edictum gate run --format raw --session-id feature-42 -- ./tool-runner
```

What `gate init` creates:

- `~/.edictum/config.json`
- `~/.edictum/rules/*.yaml`
- `~/.edictum/workflows/*.yaml`
- `~/.edictum/state/sessions.json`
- `~/.edictum/audit/wal-YYYYMMDD.jsonl`

How Gate resolves `session_id` for workflow state:

1. `--session-id`
2. `.edictum-session`
3. current git branch
4. workflow name fallback when `HEAD` is detached

If the workflow uses trusted `exec(...)` conditions, you must enable them with `--workflow-exec` during `gate init` or `gate run`.

## CLI Reference

CLI exit codes:

- `0`: success, allowed call, or no changes
- `1`: blocked call, diff detected, replay changes found, or failed tests
- `2`: usage or internal error

### Top-level commands

- `edictum version [--json]`
  Prints the CLI version, Go runtime, OS/arch, and build metadata.
- `edictum validate <files...> [--json]`
  Validates one or more YAML rulesets.
  Flags: `--json`
- `edictum check <files...> --tool <tool> --args <json> [--principal-role <role>] [--principal-user <id>] [--principal-ticket <ref>] [--environment <env>] [--json]`
  Evaluates a tool call against one or more rulesets without running the tool.
  Flags: `--tool`, `--args`, `--principal-role`, `--principal-user`, `--principal-ticket`, `--environment` (default `production`), `--json`
- `edictum diff <file1> <file2> [file3...] [--json]`
  Compares two rulesets or shows composition changes across multiple rulesets.
  Flags: `--json`
- `edictum replay <bundle> --audit-log <jsonl> [--output <path>] [--json]`
  Re-evaluates historical decision-log entries against a ruleset.
  Flags: `--audit-log`, `--output`, `--json`
- `edictum test <bundle> (--cases <yaml> | --calls <json>) [--environment <env>] [--json]`
  Runs ruleset test cases or ad-hoc tool calls.
  Flags: `--cases`, `--calls`, `--environment` (default `production`), `--json`
- `edictum gate ...`
  Workflow Gates for coding assistants.
- `edictum skill scan <path> [--threshold MEDIUM|HIGH|CRITICAL] [--structural-only] [-v|--verbose] [--json]`
  Scans skill directories for dangerous patterns.
  Flags: `--threshold` (default `MEDIUM`), `--structural-only`, `-v` / `--verbose`, `--json`

### Gate formats

`gate check` and `gate run` read JSON from stdin. Supported `--format` values are:

| Format | Expected stdin shape | Notes |
|--------|----------------------|-------|
| `claude-code` | `{"tool_name":"Read","tool_input":{...}}` | Default for `gate check`. Auto-detects Cursor payloads when Cursor-specific fields are present. |
| `cursor` | `{"tool_name":"Shell","tool_input":{...}}` | Maps `Shell` to `Bash`. |
| `copilot` | `{"toolName":"bash","toolArgs":"{\"command\":\"git status\"}"}` | `toolArgs` can be a JSON string or object. |
| `gemini` | `{"tool_name":"run_shell_command","tool_input":{...}}` | Maps Gemini tool names like `run_shell_command`, `write_file`, `read_file`, `replace_in_file`. |
| `opencode` | `{"tool":"bash","args":{...}}` | Normalizes OpenCode argument keys like `filePath` -> `file_path`. |
| `raw` | `{"tool_name":"Read","tool_input":{...}}` | No assistant-specific translation. Default for `gate run`. |

### `edictum gate` subcommands

- `edictum gate init`
  Initializes local Gate state under `~/.edictum`.
  Flags: `--server <url>`, `--api-key <key>`, `--rules <path>`, `--environment <name>` (default `production`), `--workflow <path>`, `--workflow-exec`, `--non-interactive`
- `edictum gate check`
  Evaluates stdin against rules only. This does not advance workflow stages.
  Flags: `--format <claude-code|cursor|copilot|gemini|opencode|raw>` (default `claude-code`), `--rules <path>`, `--json`
- `edictum gate run -- <command> [args...]`
  Runs the real tool execution path with workflow state, approvals, and persisted sessions.
  Flags: `--format <claude-code|cursor|copilot|gemini|opencode|raw>` (default `raw`), `--rules <path>`, `--workflow <path>`, `--session-id <id>`, `--workflow-exec`
- `edictum gate reset --stage <stage>`
  Resets a persisted workflow session to a named stage.
  Flags: `--stage <id>` (required), `--session-id <id>`, `--workflow <path>`, `--workflow-exec`
- `edictum gate install <assistant>`
  Installs the Gate hook for one assistant.
  Assistants: `claude-code`, `copilot`, `cursor`, `gemini`, `opencode`
- `edictum gate uninstall <assistant>`
  Removes the Gate hook for one assistant.
  Assistants: `claude-code`, `copilot`, `cursor`, `gemini`, `opencode`
- `edictum gate status`
  Shows current Gate config, installed assistants, pending local decision-log events, and workflow state.
  Flags: `--json`, `--session-id <id>`
- `edictum gate audit`
  Shows recent local decision-log events from the Gate WAL.
  Flags: `--limit <n>` (default `20`), `--tool <tool>`, `--decision <allow|block>`, `--json`
- `edictum gate sync`
  Flushes buffered decision-log events to the configured server endpoint.
  Flags: `--json`

### Assistant install targets

`edictum gate install` writes to the same files the source code uses today:

| Assistant | Files touched |
|-----------|---------------|
| `claude-code` | `~/.claude/settings.json` |
| `cursor` | `~/.cursor/hooks.json` |
| `copilot` | `.github/hooks/hooks.json` in the current worktree |
| `gemini` | `.gemini/settings.json` and `.gemini/hooks/edictum-gate.sh` in the current worktree |
| `opencode` | `~/.opencode/plugins/edictum-gate.ts` |

## Adapters

Every adapter exposes the same constructor:

```go
adapter := packageName.New(g, opts...)
```

Any `guard.RunOption` values passed to `New()` become default run metadata for wrapped calls. Per-call context values set with `guard.ContextWithRunOptions()` still win.

| Adapter | Import | Wrapped signature | Docs |
|---------|--------|-------------------|------|
| ADK Go | `github.com/edictum-ai/edictum-go/adapter/adkgo` | `func(context.Context, map[string]any) (any, error)` | [adapter/adkgo/README.md](adapter/adkgo/README.md) |
| LangChainGo | `github.com/edictum-ai/edictum-go/adapter/langchaingo` | `func(context.Context, string) (string, error)` | [adapter/langchaingo/README.md](adapter/langchaingo/README.md) |
| Anthropic SDK Go | `github.com/edictum-ai/edictum-go/adapter/anthropic` | `func(context.Context, json.RawMessage) (any, error)` | [adapter/anthropic/README.md](adapter/anthropic/README.md) |
| Eino | `github.com/edictum-ai/edictum-go/adapter/eino` | `func(context.Context, map[string]any) (any, error)` | [adapter/eino/README.md](adapter/eino/README.md) |
| Genkit | `github.com/edictum-ai/edictum-go/adapter/genkit` | `func(context.Context, map[string]any) (any, error)` | [adapter/genkit/README.md](adapter/genkit/README.md) |

## RunOption examples

Use run options when you want stable metadata on the decision log and session state.

### Direct `Run()` call

```go
package main

import (
	"context"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func main() {
	g, _ := guard.FromYAML("rules.yaml")

	principal := toolcall.NewPrincipal(
		toolcall.WithUserID("user-123"),
		toolcall.WithRole("reviewer"),
	)

	_, _ = g.Run(
		context.Background(),
		"Bash",
		map[string]any{"command": "go test ./..."},
		func(args map[string]any) (any, error) {
			return "ok", nil
		},
		guard.WithSessionID("session-42"),
		guard.WithParentSessionID("ticket-481"),
		guard.WithRunEnvironment("staging"),
		guard.WithRunPrincipal(&principal),
	)
}
```

### Adapter defaults plus per-call overrides

```go
package main

import (
	"context"

	"github.com/edictum-ai/edictum-go/adapter/adkgo"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/toolcall"
)

func main() {
	g, _ := guard.FromYAML("rules.yaml")

	principal := toolcall.NewPrincipal(
		toolcall.WithUserID("user-123"),
		toolcall.WithRole("builder"),
	)

	adapter := adkgo.New(
		g,
		guard.WithSessionID("default-session"),
		guard.WithParentSessionID("ticket-481"),
		guard.WithRunEnvironment("dev"),
		guard.WithRunPrincipal(&principal),
	)

	ctx := guard.ContextWithRunOptions(
		context.Background(),
		guard.WithSessionID("request-99"),
	)

	wrapped := adapter.WrapTool("Bash", func(ctx context.Context, args map[string]any) (any, error) {
		return "ok", nil
	})

	_, _ = wrapped(ctx, map[string]any{"command": "git diff"})
}
```

## Why this repo exists

Workflow Gates are the point. Rulesets matter, adapters matter, but the shipped differentiator in Go is stateful process enforcement for real assistant tool calls.

The flow looks like this:

1. The assistant emits a tool call.
2. `edictum gate run` normalizes the payload.
3. The guard evaluates rules and workflow gates.
4. The tool runs only if the current stage allows it.
5. The result and metadata land in the decision log.

That is how you get agents that actually follow the process you wrote down.

## Research

- [GAP paper](https://arxiv.org/abs/2602.16943) - 17,420 datapoints, 6 frontier models, 55-79% gap between text refusal and tool-call behavior

## Ecosystem

| Repo | Role |
|------|------|
| [edictum](https://github.com/edictum-ai/edictum) | Python SDK |
| [edictum-ts](https://github.com/edictum-ai/edictum-ts) | TypeScript SDK |
| [edictum-go](https://github.com/edictum-ai/edictum-go) | Go SDK |
| [edictum-console](https://github.com/edictum-ai/edictum-console) | Dashboard and server APIs |
| [edictum-schemas](https://github.com/edictum-ai/edictum-schemas) | Shared YAML schema |
| [edictum-demo](https://github.com/edictum-ai/edictum-demo) | Demos and integration examples |

## Security reports

See [SECURITY.md](SECURITY.md).

## License

MIT - see [LICENSE](LICENSE).
