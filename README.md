# edictum-go

Runtime contract enforcement for AI agent tool calls. Go port of [edictum](https://github.com/edictum-ai/edictum) with full feature parity.

```go
guard := guard.New(
    guard.WithContracts(
        contract.Precondition{
            Name: "no-rm-rf", Tool: "Bash",
            Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
                if strings.Contains(env.BashCommand(), "rm -rf") {
                    return contract.Fail("Cannot run rm -rf"), nil
                }
                return contract.Pass(), nil
            },
        },
    ),
)

// Wraps any tool with governance — pre-checks, execution, post-checks, audit
result, err := guard.Run(ctx, "Bash", args, toolCallable)
```

## What it does

Edictum sits between your AI agent and its tools. Every tool call passes through a deterministic governance pipeline:

1. **Attempt limits** — cap total pre-execution events
2. **Before hooks** — custom deny/allow logic
3. **Preconditions** — contract checks before execution
4. **Sandbox contracts** — path, command, and domain boundaries
5. **Session contracts** — cross-turn state checks
6. **Execution limits** — cap tool calls globally and per-tool
7. **Tool execution** — the actual tool runs
8. **Postconditions** — warn, redact, or suppress output
9. **Audit** — structured event logging for every decision

Denied calls never execute. Observe mode logs what *would* be denied without blocking.

## Install

```bash
go get github.com/edictum-ai/edictum-go
```

Requires Go 1.25+.

## Quick start

### Programmatic contracts

```go
import (
    "github.com/edictum-ai/edictum-go/contract"
    "github.com/edictum-ai/edictum-go/guard"
)

g := guard.New(
    guard.WithEnvironment("production"),
    guard.WithMode("enforce"), // or "observe"
    guard.WithContracts(
        contract.Precondition{
            Name: "deny-sensitive-paths", Tool: "*",
            Check: func(_ context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
                if strings.Contains(env.FilePath(), "/.ssh/") {
                    return contract.Fail("Access to .ssh is denied"), nil
                }
                return contract.Pass(), nil
            },
        },
    ),
    guard.WithOnDeny(func(env envelope.ToolEnvelope, reason, name string) {
        log.Printf("DENIED: %s — %s", env.ToolName(), reason)
    }),
)
```

### YAML contracts

```yaml
apiVersion: edictum/v1
kind: ContractBundle
defaults:
  mode: enforce
contracts:
  - id: no-destructive-bash
    type: pre
    tool: Bash
    when:
      args.command:
        contains_any: ["rm -rf", "DROP TABLE", "FORMAT"]
    then:
      effect: deny
      message: "Destructive command denied: {args.command}"
```

```go
bundle, hash, _ := yaml.LoadBundle("contracts.yaml")
compiled, _ := yaml.Compile(bundle)
// Pass compiled contracts to guard via WithContracts or guard.Reload
```

### Framework adapters

```go
import "github.com/edictum-ai/edictum-go/adapter/adkgo"

adapter := adkgo.New(g)
wrappedTool := adapter.WrapTool("Bash", originalToolFunc)
// Use wrappedTool in your ADK agent — governance is transparent
```

Five adapters included:

| Adapter | Framework | Import |
|---------|-----------|--------|
| `adkgo` | Google ADK Go | `adapter/adkgo` |
| `langchaingo` | LangChainGo | `adapter/langchaingo` |
| `eino` | Eino/CloudWeGo | `adapter/eino` |
| `anthropic` | Anthropic SDK Go | `adapter/anthropic` |
| `genkit` | Firebase Genkit | `adapter/genkit` |

All adapters are thin wrappers around `guard.Run()` with zero external framework dependencies.

### Server SDK

Connect to [edictum-console](https://github.com/edictum-ai/edictum-console) for remote contract management:

```go
import "github.com/edictum-ai/edictum-go/server"

client, _ := server.NewClient(server.ClientConfig{
    BaseURL:  "https://console.edictum.ai",
    APIKey:   os.Getenv("EDICTUM_API_KEY"),
    AgentID:  "my-agent",
})

// HTTP-backed session storage
backend := server.NewBackend(client)

// Batched audit sink
sink := server.NewAuditSink(client)

// SSE hot-reload with Ed25519 verification
watcher := server.NewSSEWatcher(client, server.WithReloader(myGuard))
go watcher.Watch(ctx)
```

## Architecture

```
edictum-go/
├── pipeline/        # 5-stage governance pipeline
├── contract/        # Verdict, Precondition, Postcondition, SessionContract
├── envelope/        # ToolEnvelope, BashClassifier, Principal, ToolRegistry
├── guard/           # Top-level API — Run(), Evaluate(), options, callbacks
├── session/         # Session counters, MemoryBackend
├── audit/           # CollectingSink, CompositeSink, StdoutSink
├── redaction/       # RedactionPolicy (word-boundary matching, secret detection)
├── sandbox/         # Path/command/domain sandboxing
├── yaml/            # YAML contract bundle loader, evaluator, compiler
├── server/          # Server SDK — HTTP client, SSE, Ed25519, approval
├── approval/        # Approval backend interface
├── adapter/         # Framework adapters (5)
└── internal/        # shlex tokenizer, deepcopy utility
```

**Core runs fully standalone.** No server dependency. No adapter dependency. No framework dependency.

## Key design decisions

- **Go 1.25+** — oldest supported release
- **Zero runtime deps in core** — optional: `gopkg.in/yaml.v3` for YAML engine
- **Struct literals for contracts** — compile-time validated, explicit
- **`context.Context` everywhere** — every pipeline, session, and audit method
- **Unexported fields + getters** — immutability enforced by API design
- **`sync.Mutex` for shared state** — Go is multi-threaded, `go test -race` must pass
- **Fail-closed on every error path** — network errors propagate, never return stale data
- **Value receivers for immutable types** — copying IS the immutability mechanism

## Feature parity

Full parity with [edictum](https://github.com/edictum-ai/edictum) Python v0.15.0 across 147 features in 12 categories:

| Category | Features |
|----------|----------|
| Core Pipeline | 27 |
| ToolEnvelope & Classification | 18 |
| YAML Engine | 32 |
| Sandbox | 14 |
| Session & Storage | 11 |
| Audit & Redaction | 20 |
| Guard Class | 16 |
| Hooks & Contracts API | 9 |
| Callbacks & DX | 8 |
| Server SDK | 14 |
| Adapter Parity | 5 adapters |
| Security Adversarial | 35 tests |

562 tests. All passing with `-race`.

## Security

This is a security product. See [SECURITY.md](SECURITY.md) for the vulnerability reporting process.

Every security boundary has bypass tests. Every error path fails closed. Every shared state is mutex-protected. Every input used in storage keys is validated. Every regex input is capped at 10,000 characters.

## License

MIT — see [LICENSE](LICENSE).

## Ecosystem

- **[edictum](https://github.com/edictum-ai/edictum)** — Python core library (PyPI: `edictum`)
- **[edictum-go](https://github.com/edictum-ai/edictum-go)** — Go core library (this repo)
- **[edictum-console](https://github.com/edictum-ai/edictum-console)** — Self-hostable server for contract management
