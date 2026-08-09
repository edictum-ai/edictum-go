# Changelog

## Unreleased

### Breaking Changes

- policy-block exits changed from 1 to each supported hook protocol's status:
  `claude-code` and `copilot` now exit 2, while `opencode` now exits 0 and
  communicates the block with `allow: false` on stdout; integrations that
  inspect raw exit statuses must update their checks

### Removed

- removed the Cursor and Gemini CLI gate formats and installers because they
  could not be verified against current live hosts; users should stay on the
  previous release or migrate to Claude Code, Copilot, or OpenCode; cleanup-only
  `gate uninstall cursor` and `gate uninstall gemini` commands remain available

## v0.5.0 - 2026-04-15

### Added

- workflow shared semantics now match the v0.18 line: wildcard stage tools,
  terminal stages, MCP evidence checks, and ruleset inheritance via `extends`

### Fixed

- workflow runtime stage advancement now blocks on failing checks and aligns
  with the current Python/TypeScript semantics

### Breaking Changes

- none

## v0.4.0 - 2026-04-05

### Added

- adapter constructors now accept default `guard.RunOption` values, including
  session, environment, lineage, and principal overrides used by external
  consumers such as `edictum-demo`
- workflow runtimes now expose non-destructive `SetStage` moves, richer
  persisted `workflow.State`, and `metadata.version` on workflow definitions
- audit events now include session lineage fields plus workflow progress actions
  such as `workflow_state_updated`
- embedded approval flows now have an in-memory approval backend and broader
  workflow adapter conformance coverage

### Fixed

- server audit sink payloads now match the `/v1/events` API shape used by the
  control plane

### Breaking Changes

- none
