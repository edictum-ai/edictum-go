# CLAUDE.md — Edictum Go

> Runtime contract enforcement for AI agent tool calls. Go port of the edictum Python library with full feature parity.

## What is Edictum

Runtime contract enforcement for AI agent tool calls. Deterministic pipeline: preconditions, postconditions, session contracts, principal-aware enforcement. Framework adapters (Google ADK Go, LangChainGo, Eino, Anthropic SDK Go, Genkit). Zero runtime deps in core. Full feature parity with the Python library (`edictum` on PyPI, v0.15.0).

Current version: 0.1.0 (`github.com/edictum-ai/edictum-go`)

## THE ONE RULE

**Core runs fully standalone. No server dependency. No adapter dependency. No framework dependency.**

Core provides interfaces and implementations. The server package provides HTTP-backed implementations. Adapters are thin translation layers — governance logic stays in the pipeline.

## Architecture: Single Module, Subpackages

```
edictum-go/
├── pipeline/              # Core 5-stage governance pipeline
├── envelope/              # ToolEnvelope, BashClassifier, Principal, ToolRegistry
├── contract/              # Precondition, Postcondition, SessionContract, Verdict
├── session/               # Session, StorageBackend, MemoryBackend
├── audit/                 # AuditSink, CompositeSink, FileSink, CollectingSink
├── redaction/             # RedactionPolicy
├── approval/              # ApprovalBackend, LocalApprovalBackend
├── yaml/                  # YAML contract bundle loader (optional dep)
├── sandbox/               # Path/command/domain sandbox
├── guard/                 # Top-level Edictum guard (constructor, reload, from_yaml)
├── adapter/
│   ├── adkgo/             # Google ADK Go adapter
│   ├── langchaingo/       # LangChainGo adapter
│   ├── eino/              # Eino/CloudWeGo adapter
│   ├── anthropic/         # Anthropic SDK Go adapter
│   └── genkit/            # Genkit Go adapter
├── server/                # Server SDK (HTTP client, SSE, audit sink)
└── internal/
    ├── shlex/             # Shell tokenizer (security-critical)
    └── deepcopy/          # Deep copy utilities
```

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Go 1.22+ | Latest stable, generics, errors.Join, slices/maps |
| Build | `go build` | Standard toolchain, no third-party build tool |
| Test | `go test` + testify | Standard testing, testify for assertions |
| Lint | golangci-lint | gosec, staticcheck, govet, errcheck |
| Module | Single `go.mod` | Subpackages via Go import paths |
| Race detection | `go test -race` | Every CI run — concurrency is real in Go |

## Non-Negotiable Principles

1. **Full feature parity with Python.** 147 features across 12 categories. Every feature has a parity test ID. If Python passes and Go fails, it's a bug.
2. **Security is non-negotiable.** This is a security product. No shortcuts, no "good enough", no deferred fixes for vulnerabilities. Fail closed on every error path.
3. **Zero runtime deps in core.** Optional: `gopkg.in/yaml.v3`, `github.com/santhosh-tekuri/jsonschema`, `go.opentelemetry.io/otel`. Core runs with stdlib only.
4. **Struct literals for contracts.** Interfaces define protocols. Structs define data. Functional options for optional config. No reflection magic.
5. **`context.Context` everywhere.** Every pipeline, session, and audit sink method takes `ctx context.Context` as first parameter.
6. **Immutability by API design.** Unexported fields + getter methods + value receivers. No `Object.freeze()` in Go — enforce via encapsulation.
7. **Adapters are thin.** All governance logic lives in GovernancePipeline. Adapters only translate between framework input/output and the pipeline.
8. **Adversarial tests before ship.** Every security boundary has bypass tests. Positive tests prove it works. Adversarial tests prove it doesn't break.
9. **`go test -race` must always pass.** Go is multi-threaded — race conditions are real. Every shared state needs mutex protection.

## Coding Standards

### Go

- **No `any` unless genuinely unavoidable** and documented with a comment explaining why.
- **Typed constants for enums.** `type SideEffect string` with `const` block. No iota for string enums.
- **Interfaces for protocols.** `StorageBackend`, `AuditSink`, `ApprovalBackend` are all interfaces.
- **`context.Context` as first param.** Every method that does I/O or could be cancelled.
- **Errors, not panics.** Every function that can fail returns `error`. Use `errors.Is()`/`errors.As()` for typed errors.
- **`sync.Mutex` / `sync.RWMutex`** for shared state. Document what each mutex protects.
- **Unexported fields + exported getters** for immutable data types (ToolEnvelope, Principal, Verdict).
- **Value receivers** for immutable types, pointer receivers for mutable types.
- **`errors.Join()`** for aggregating multiple errors (replaces AggregateError).
- **No `init()` functions.** Explicit initialization only.
- **Generics where natural.** `ToolEnvelope[T any]` for typed args. Don't force generics where `any` suffices.

### General

- **Small, focused files (< 200 lines).** If a file grows past 200 lines, split it. Violations need explicit approval.
- **Conventional commits** (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
- **No premature abstraction.** Don't build extension points until there's a second user.
- **No over-engineering.** Only make changes that are directly requested or clearly necessary.

## Contract API Design

Contracts use **struct literals** with Go interfaces. Idiomatic, explicit, compile-time validated:

```go
noRm := contract.Precondition{
    Tool: "Bash",
    Check: func(ctx context.Context, env envelope.ToolEnvelope) (contract.Verdict, error) {
        if strings.Contains(env.BashCommand(), "rm -rf") {
            return contract.Fail("Cannot run rm -rf"), nil
        }
        return contract.Pass(), nil
    },
}

guard := guard.New(guard.WithContracts(noRm))
```

## Terminology Enforcement

Inherited from the Python library. ALL code, comments, docstrings, CLI output, and docs MUST use canonical terms:

| Wrong | Correct |
|-------|---------|
| rule / rules (in prose) | contract / contracts |
| blocked | denied |
| engine (for runtime) | pipeline |
| shadow mode | observe mode |
| alert | finding |

**No exceptions.**

## API Design Checklist

Before adding any new public API:

- **Every accepted parameter has an observable effect.** If unimplemented, return error — never silently ignore.
- **Collection parameters have documented merge semantics.** Document whether it EXTENDS or REPLACES defaults.
- **Deny decisions propagate end-to-end.** Trace deny through every adapter. Never return "allow" after a deny.
- **Callbacks fire exactly once.** Assert callback count == 1 in tests.
- **All adapters handle the new feature.** Run adapter parity tests after any change.

## Security Review Checklist

Before merging ANY code that touches these areas:

- **Path handling**: Uses `filepath.EvalSymlinks()` not just `filepath.Clean()`. Test with symlinks.
- **Shell command classification**: All shell metacharacters enumerated. Test with: `\n`, `\r`, `|`, `;`, `&&`, `||`, `$()`, `` ` ``, `${}`, `<()`, `<<`, `>`, `>>`
- **Error handling in backends**: `Get()` and `Increment()` fail-closed. Network errors propagate, only 404/missing returns nil.
- **Audit action accuracy**: Audit events reflect what actually happened. Timeouts emit TIMEOUT, not GRANTED.
- **Input validation**: toolName, sessionId, any string used in storage keys validated for control characters.
- **Regex DoS**: All regex input capped at 10,000 characters.
- **Concurrency**: Every shared state protected by mutex. `go test -race` passes.

## Behavior Test Requirement

Every public API parameter MUST have a behavior test.

A behavior test answers: "What observable effect does this parameter have?"

- Tests the parameter's effect through the public API
- Asserts a concrete difference between passing and not passing the parameter
- Lives in the corresponding package's `_test.go` files
- Keep test files focused: one file per module, under 200 lines

## Negative Security Test Requirement

Every security boundary MUST have bypass tests — tests that attempt to circumvent the boundary and verify the attempt is caught. Named with `TestSecurity` prefix for CI filtering.

Examples:
- Sandbox: symlink escape, double-encoding, null byte injection
- BashClassifier: every shell metacharacter individually
- Session limits: concurrent access patterns (goroutines)
- Input validation: null bytes, control characters, path separators in toolName

## Feature Parity Matrix

147 features across 12 categories must pass in Python, TypeScript, AND Go. See memory file `project_parity_matrix_detail.md` for the full matrix with test IDs.

Cross-language validation: shared YAML contract bundles + JSON input/output fixtures. Same input → same output → parity proven.

## Bug & Issue Triage Rule

When working in the project, if a bug, security issue, or problem is detected that was NOT in the initial prompt:

1. Triage — assess severity and whether it blocks current work
2. If fixable now without derailing the task → fix immediately and mention it
3. If not fixable now → create a GitHub issue in the repo with proper labels
4. **Never silently ignore a discovered issue**

## Build & Test

```bash
go build ./...                        # build all packages
go test ./...                         # test all packages
go test -race ./...                   # test with race detector
go test -run "TestSecurity" ./...     # security boundary tests only
go test ./pipeline/...                # test pipeline only
go test ./envelope/...                # test envelope only
golangci-lint run ./...               # lint
go vet ./...                          # vet
```

## Pre-Merge Verification

Every change MUST pass these checks before committing:

```bash
go build ./...                        # all packages build
go test ./...                         # full test suite
go test -race ./...                   # race detector
golangci-lint run ./...               # lint
go vet ./...                          # vet
# If touching adapters:
go test -run "TestAdapterParity" ./adapter/...
```

## YAML Schema

The contract schema lives in the `edictum-schemas` repo — single source of truth. This repo embeds it via `//go:embed`.

- `apiVersion: edictum/v1`, `kind: ContractBundle`
- Contract types: `type: pre` (deny/approve), `type: post` (warn/redact/deny), `type: session` (deny only), `type: sandbox` (allowlist-based)
- Conditions: `when:` with boolean AST (`all/any/not`) and leaves (`selector: {operator: value}`)
- 15 operators: exists, equals, not_equals, in, not_in, contains, contains_any, starts_with, ends_with, matches, matches_any, gt, gte, lt, lte
- Missing fields evaluate to `false`. Type mismatches yield deny/warn + `policyError: true`

## Ecosystem Context

Edictum is five repos that work together:

- **edictum** (core Python): `edictum-ai/edictum` — MIT Python library. PyPI: `edictum`.
- **edictum-ts** (core TypeScript): `edictum-ai/edictum-ts` — MIT TypeScript library. npm: `@edictum/core`.
- **edictum-go** (core Go): THIS REPO — MIT Go library. `github.com/edictum-ai/edictum-go`.
- **edictum-console** (server): `edictum-ai/edictum-console` — Self-hostable FastAPI + React SPA.
- **edictum-schemas** (shared): `edictum-ai/edictum-schemas` — Shared YAML contract schema.

All three core libraries (Python, TS, and Go) work standalone. Console is an optional enhancement. Schema repo is the single source of truth for the contract format.
