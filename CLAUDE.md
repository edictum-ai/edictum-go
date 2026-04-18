# CLAUDE.md - Edictum Go

> Go SDK for Edictum. Rules for AI agents, Workflow Gates for coding assistants, five Go adapters, zero runtime deps in core.

## What ships here

This repo is the Go SDK at `github.com/edictum-ai/edictum-go`.

Current version: `0.4.0`

Feature order in this repo:

1. Workflow Gates
2. Rules engine
3. Cross-framework adapters
4. Human approvals
5. Decision log

The short version:

- `guard.Run()` is the embedded path.
- `edictum gate run` is the CLI path for real assistant tool calls.
- `edictum gate check` is rules-only preflight.
- Server connectivity is optional.

## Positioning

Edictum is a developer agent behavior platform.

What it is not:

- not an orchestrator
- not prompt tooling
- not a chat moderation layer
- not a pure dashboard product

The point is simple: write rules and workflow stages outside the model, then block tool calls when the agent ignores them.

## The One Rule

**Core runs standalone. No server required. No adapter required. No framework required.**

Core owns the rules pipeline, workflow runtime, session state, approvals, and decision-log emission.

Adapters only translate framework-specific tool signatures into `guard.Run()`.

## Architecture

```text
edictum-go/
├── adapter/             # ADK Go, LangChainGo, Anthropic SDK Go, Eino, Genkit
├── approval/            # Approval backends and approval request types
├── audit/               # Structured decision-log events and sinks
├── cmd/edictum/         # CLI, including Workflow Gates
├── guard/               # Top-level guard constructors and Run/Evaluate APIs
├── pipeline/            # Pre, post, session, sandbox evaluation pipeline
├── redaction/           # Output redaction policy
├── rule/                # Rule types
├── sandbox/             # Path, command, and domain allowlists
├── server/              # Optional HTTP client, approval backend, audit sink
├── session/             # Persistent session state backends
├── skill/               # Skill scanner used by the CLI
├── telemetry/           # OpenTelemetry integration
├── toolcall/            # ToolCall and Principal types
├── workflow/            # Workflow definitions and runtime
└── yaml/                # Ruleset loading, validation, compilation
```

## Core ideas

### Workflow Gates come first

Workflow Gates are the differentiator in this repo.

They let you say:

- read the spec before editing
- ask for approval before running Bash
- run `git diff` before leaving implement
- make tests pass before the task is complete

The real workflow shape in this repo is:

- `kind: Workflow`
- `stages`
- `entry`
- `exit`
- `checks`
- `approval`

Do not document or generate old `gates.before` / `gates.after` examples. They are not the live format here.

### Rulesets are still the core API

Rulesets use:

- `apiVersion: edictum/v1`
- `kind: Ruleset`
- `rules:`
- `when:`
- `then:`
- `then.action`

Rule types:

- `pre`
- `post`
- `session`
- `sandbox`

### Adapters stay thin

Every Go adapter uses the same pattern:

```go
adapter := packageName.New(g, opts...)
wrapped := adapter.WrapTool("ToolName", original)
```

Any `guard.RunOption` values passed to `New()` become default metadata for wrapped calls.

## Terminology

Use current M1 naming in prose, comments, docs, and CLI help text.

Preferred words:

- `rule` / `rules`
- `ruleset`
- `behavior`
- `workflow gates`
- `pipeline`
- `violations`
- `blocked`
- `decision log`
- `Dashboard`
- `agent overview`
- `observe mode`

For code identifiers, keep the shipped API unless the task explicitly says to rename it.

## YAML and runtime rules

### Ruleset YAML

- `kind: Ruleset`
- top-level collection is `rules:`
- pre/post rules use `when:` and `then:`
- actions use `block`, `ask`, `warn`, or `redact`
- top-level defaults use `defaults.mode: enforce|observe`

### Workflow YAML

- `kind: Workflow`
- stages are stateful
- gate conditions live in `entry:` and `exit:`
- command history checks live in `checks:`
- human pauses live in `approval:`
- trusted `exec(...)` conditions require explicit opt-in

### CLI behavior

- `edictum gate check` evaluates rules only
- `edictum gate run` runs the real tool path and advances workflow state
- workflow session IDs resolve from `--session-id`, `.edictum-session`, git branch, or workflow name fallback

## Tech stack

| Layer | Technology | Notes |
|-------|------------|-------|
| Language | Go 1.25+ | oldest supported release |
| Build | `go build` | standard toolchain |
| Test | `go test` | `-race` must stay green |
| Lint | `golangci-lint` | includes `govet`, `gosec`, `staticcheck` |
| Module | single `go.mod` | subpackages via import paths |

## Non-negotiables

1. Core stays usable without the server.
2. Adapters stay thin.
3. Fail-closed behavior matters. Do not turn rule or workflow errors into silent allows.
4. `go test -race ./...` must pass.
5. Shared semantics must stay aligned with Python and TypeScript.
6. Public parameters need behavior tests.
7. Workflow Gates and CLI docs must match source, not aspirational docs.

## Go standards

- Prefer concrete types and small interfaces.
- Use `context.Context` as the first parameter for work that can block or be cancelled.
- Return errors, do not panic, unless the process truly cannot continue.
- Protect shared mutable state with `sync.Mutex` or `sync.RWMutex`.
- Keep exported APIs explicit. Do not add parameters that have no observable effect.
- Keep files focused. If a file starts sprawling, split it.
- Do not push rule logic into adapters.

## Public API checklist

Before adding or changing a public API:

- Every accepted parameter must change behavior in a testable way.
- Document merge semantics for collections and defaults.
- Make sure blocked decisions propagate end-to-end.
- Make sure callbacks fire exactly once.
- Run the adapter tests if the change touches shared execution behavior.

## Workflow and parity checklist

If the change affects ruleset semantics, workflow behavior, YAML validation, or shared fixtures:

1. update shared fixtures if needed
2. keep Go aligned with Python and TypeScript
3. run the shared-fixture tests
4. do not ship source/docs drift for workflow YAML

## Bug triage rule

If you notice a bug that was not in the original prompt:

1. decide whether it blocks the current task
2. fix it now if the fix is small and directly adjacent
3. otherwise raise it explicitly
4. do not silently ignore it

## Build and test

```bash
gofmt -l .
go build ./...
go test ./...
go test -race ./...
go test -run "TestSecurity" ./...
golangci-lint run ./...
```

If you touch adapters:

```bash
go test ./adapter/...
```

If you touch shared YAML behavior:

```bash
EDICTUM_FIXTURES_DIR=edictum-schemas/fixtures/rejection EDICTUM_CONFORMANCE_REQUIRED=1 \
  go test -v -run TestSharedRejectionFixtures ./yaml/...
```

## Pre-merge checks

Every change should leave the repo in this state:

- `gofmt -l .` returns nothing
- `go build ./...` passes
- `go test -race ./...` passes
- adapter tests pass when adapter behavior changed
- docs match the current CLI and YAML behavior

## Ecosystem

Relevant repos:

- `edictum`: Python SDK
- `edictum-ts`: TypeScript SDK
- `edictum-go`: this repo
- `edictum-console`: Dashboard and server APIs
- `edictum-schemas`: shared schema and fixtures

All three SDKs should stay semantically aligned.
