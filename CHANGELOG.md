# Changelog

## v0.6.0 - 2026-08-10

### Security

**The Cursor and Gemini gate formats did not reliably block a denied tool call.**

- **Cursor.** The emitter wrote `{"decision": "block"}`. Cursor's hook protocol reads
  `permission: "allow" | "deny"` — a field it was never sent. The decision was discarded. A normal
  policy block also exited 1, which Cursor treats as non-blocking.
- **Gemini.** The generated wrapper script wrote the valid deny payload to **stderr** and exited 1.
  Gemini treats exit 1 as a non-blocking warning, so the decision never reached the host. The
  wrapper carried a comment describing this path as fail-closed; it was not.

In both cases the policy engine reached the correct decision and then failed to communicate it in a
form the host honours, so the tool ran. **Both formats are removed in this release** rather than
shipped with a fix we cannot verify against a current live host — see *Removed*.

`claude-code`, `copilot` and `opencode` were checked against their published protocols and now
signal a block on the channel each host actually reads. Claude Code behaviour was additionally
verified by running the real client.

**Policy blocks now use each host's own blocking signal.** Previously every format exited 1 on a
policy block. On hosts that only parse hook JSON on a successful exit, that reduced the decision to
a single channel with no fallback. See *Breaking Changes* for the new exit codes.

If you ran the gate with `--format cursor` or `--format gemini`, treat any period where you relied
on it as ungated, and check your audit log for tool calls you expected to be blocked.

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

### Fixed

- the OpenCode plugin now blocks when the gate exits non-zero, including when it
  produces no output or output that says allow; previously an empty response
  returned early and the tool ran

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
