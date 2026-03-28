# Contributing to Edictum Go SDK

## Key design decisions

- **Go 1.25+** -- oldest supported release
- **Zero runtime deps in core** -- optional: `gopkg.in/yaml.v3` for YAML support
- **Struct literals for rules** -- compile-time validated, explicit
- **`context.Context` everywhere** -- every pipeline, session, and audit method
- **Unexported fields + getters** -- immutability enforced by API design
- **`sync.Mutex` for shared state** -- Go is multi-threaded, `go test -race` must pass
- **Fail-closed on every error path** -- network errors propagate, never return stale data
- **Value receivers for immutable types** -- copying IS the immutability mechanism

## Architecture

```
edictum-go/
├── pipeline/        # 5-stage check pipeline
├── rule/            # Decision, Precondition, Postcondition, SessionRule
├── toolcall/        # ToolCall, BashClassifier, Principal, ToolRegistry
├── guard/           # Top-level API — Run(), Evaluate(), options, callbacks
├── session/         # Session counters, MemoryBackend
├── audit/           # CollectingSink, CompositeSink, StdoutSink
├── redaction/       # RedactionPolicy (word-boundary matching, secret detection)
├── sandbox/         # Path/command/domain sandboxing
├── yaml/            # YAML ruleset loader, evaluator, compiler
├── server/          # Server SDK — HTTP client, SSE, Ed25519, approval
├── approval/        # Approval backend interface
├── adapter/         # Framework adapters (5)
└── internal/        # shlex tokenizer, deepcopy utility
```

**Core runs fully standalone.** No server dependency. No adapter dependency. No framework dependency.

## Running tests

```bash
gofmt -l .
go test ./... -race -count=1
```

## Security

This is a security product. Every security boundary must have bypass tests. See [SECURITY.md](SECURITY.md) for the vulnerability reporting process.
