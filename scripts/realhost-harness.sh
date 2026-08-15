#!/bin/bash
# realhost-harness.sh — real-host harness skeleton (0.6d runner proof).
#
# Purpose (L0.4): prove that a maintainer-dispatched workflow on the
# edictum-realhost runner can drive the installed coding-agent CLIs and
# that its result is trustworthy: a hook that does not run fails the run.
#
# What this proves:
#   - Claude Code, Copilot CLI and OpenCode are installed and usable on the
#     host; a missing CLI fails the run (never skips).
#   - A PreToolUse seam of each host fires when the CLI is driven headless:
#       claude-code  hooks.PreToolUse command hook via --settings
#                    (same shape as `edictum gate install claude-code`)
#       copilot      user-level ~/.copilot/hooks preToolUse command hook,
#                    run-scoped: installed by this script, removed on exit.
#                    The repo-level .github/hooks/hooks.json shape that
#                    `edictum gate install copilot` writes does NOT load in
#                    copilot -p print mode (upstream github/copilot-cli#3345,
#                    verified locally on 1.0.79), so the headless probe uses
#                    the user-level seam, which does load.
#       opencode     project plugin tool.execute.before
#                    (same shape as the gate plugin)
#   - Missing hook evidence fails the run. A CLI run without proof that the
#     hook seam fired is a red run, not a green one.
#
# What this does NOT prove: gate enforcement (blocked calls, session limits,
# workflow stages, audit). That is the full 0.6d acceptance harness owned by
# the gate lane; this skeleton only proves the runner and the hook seams.
#
# Environment:
#   REALHOST_BREAK_HOOK=1  make every probe hook a silent no-op (records
#                          nothing); the run must go red. Wired to the
#                          break-hook dispatch input of realhost-harness.yml.
#   REALHOST_LOG_DIR       directory for logs and probe evidence (default:
#                          a fresh temp dir). The workflow points this at the
#                          workspace and uploads it as an artifact.
#
# Runner host requirements:
#   PATH must contain ~/.local/bin (claude), /opt/homebrew/bin (opencode)
#   and ~/.local/share/fnm/aliases/default/bin (node; the copilot CLI is an
#   npm loader and must run under the fnm node, not Homebrew node - on
#   2026-08-15 Homebrew node 25.8.2 was dyld-broken and aborted copilot).
#   The fnm bin directory must precede /opt/homebrew/bin.
#   Credentials are runner-local user accounts (Claude Code
#   OAuth under ~/.claude, Copilot CLI auth under ~/.copilot, OpenCode auth
#   under ~/.local/share/opencode/auth.json). Nothing is stored in the repo.
#
# Every host runs in its own scratch directory. The copilot seam is the one
# exception to "no user-level config": user-level hooks are the only hook
# location Copilot CLI loads in print mode, so this script installs
# ~/.copilot/hooks/edictum-realhost-probe.json for the duration of the run
# and removes it on exit (a stale copy is also removed at start).

set -u
set -o pipefail

LOG_DIR="${REALHOST_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/realhost-harness.XXXXXX")}"
WORK_DIR="$LOG_DIR/work"
mkdir -p "$WORK_DIR"

COPILOT_HOOK_FILE="$HOME/.copilot/hooks/edictum-realhost-probe.json"
rm -f "$COPILOT_HOOK_FILE"
cleanup() { rm -f "$COPILOT_HOOK_FILE"; }
trap cleanup EXIT INT TERM

FAILURES=""

log() { printf '%s\n' "$*"; }

fail() {
  FAILURES="$FAILURES
- $*"
  log "FAIL: $*"
}

# write_probe_hook <hook-path> <events-path>
# The log path and the break decision are baked in at generation time; the
# hook does not depend on the parent environment being inherited.
write_probe_hook() {
  if [ "${REALHOST_BREAK_HOOK:-0}" = "1" ]; then
    cat > "$1" <<'EOF'
#!/bin/sh
# Deliberately broken hook (REALHOST_BREAK_HOOK=1): exits 0 without
# recording evidence. The harness must fail the run because of that.
exit 0
EOF
  else
    cat > "$1" <<EOF
#!/bin/sh
# realhost harness probe — records the hook payload, allows everything.
printf '{"probe_time":"%s"}' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$2"
cat >> "$2"
printf '\n' >> "$2"
exit 0
EOF
  fi
  chmod +x "$1"
}

require_cli() { # $1 = binary, $2 = host label
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "$2: $1 not found on PATH"
    return 1
  fi
  return 0
}

check_hook_evidence() { # $1 = host label, $2 = events file
  if [ ! -s "$2" ]; then
    fail "$1: no hook evidence ($2 is empty or missing) — the PreToolUse hook did not run"
    return 1
  fi
  log "$1: hook evidence recorded ($(wc -l < "$2" | tr -d ' ') event(s))"
  return 0
}

run_cli_probe() { # $1 = host label; remaining args: CLI command
  local host="$1"
  shift
  log "$host: running headless probe"
  if "$@" > "$LOG_DIR/$host.out" 2> "$LOG_DIR/$host.err"; then
    log "$host: CLI exited 0"
  else
    fail "$host: CLI exited non-zero (see $host.err)"
  fi
}

# ---------------------------------------------------------------------------
# Claude Code — hooks.PreToolUse command hook, delivered via --settings so no
# user config is touched (gate install shape: cmd/edictum/gate_assistants.go).
# ---------------------------------------------------------------------------
run_claude_code() {
  local host="claude-code"
  local dir="$WORK_DIR/$host"
  local events="$LOG_DIR/$host.events.jsonl"
  mkdir -p "$dir"

  require_cli claude "$host" || return 0
  claude --version > "$LOG_DIR/$host.version" 2>&1

  write_probe_hook "$dir/probe-hook.sh" "$events"
  cat > "$dir/settings.json" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "\"$dir/probe-hook.sh\""
          }
        ]
      }
    ]
  }
}
EOF

  (cd "$dir" && run_cli_probe "$host" \
    claude -p "Use the Bash tool to run exactly this command and reply with its output: echo edictum-probe-$host" \
      --settings "$dir/settings.json" \
      --allowedTools "Bash")

  check_hook_evidence "$host" "$events"
}

# ---------------------------------------------------------------------------
# Copilot CLI — user-level preToolUse command hook, the only hook location
# Copilot loads in print mode (gate shape for the hook entry itself:
# cmd/edictum/gate_assistants_ext.go; location differs because of
# github/copilot-cli#3345 — repo-level .github/hooks/hooks.json does not
# load under copilot -p).
# ---------------------------------------------------------------------------
run_copilot() {
  local host="copilot"
  local dir="$WORK_DIR/$host"
  local events="$LOG_DIR/$host.events.jsonl"
  mkdir -p "$dir"

  require_cli copilot "$host" || return 0
  copilot --version > "$LOG_DIR/$host.version" 2>&1

  write_probe_hook "$dir/probe-hook.sh" "$events"
  mkdir -p "$HOME/.copilot/hooks"
  cat > "$COPILOT_HOOK_FILE" <<EOF
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "\"$dir/probe-hook.sh\"",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

  (cd "$dir" && run_cli_probe "$host" \
    copilot -p "Run exactly this shell command and reply with its output: echo edictum-probe-$host" \
      --allow-all-tools)

  check_hook_evidence "$host" "$events"
}

# ---------------------------------------------------------------------------
# OpenCode — project plugin with a tool.execute.before hook (gate plugin
# shape: cmd/edictum/gate_assistants_detect.go), scoped to the scratch
# project via opencode.json so no user plugin is installed.
# ---------------------------------------------------------------------------
run_opencode() {
  local host="opencode"
  local dir="$WORK_DIR/$host"
  local events="$LOG_DIR/$host.events.jsonl"
  mkdir -p "$dir"

  require_cli opencode "$host" || return 0
  opencode --version > "$LOG_DIR/$host.version" 2>&1

  cat > "$dir/opencode.json" <<EOF
{
  "plugin": ["./probe.ts"],
  "permission": {
    "bash": "allow"
  }
}
EOF
  if [ "${REALHOST_BREAK_HOOK:-0}" = "1" ]; then
    cat > "$dir/probe.ts" <<'EOF'
// Deliberately broken probe plugin (REALHOST_BREAK_HOOK=1): returns
// without recording evidence. The harness must fail the run.
export const EdictumProbe = async () => {
  return {
    "tool.execute.before": async () => {},
  };
};
EOF
  else
    cat > "$dir/probe.ts" <<EOF
// Edictum real-host harness probe plugin (skeleton). Mirrors the gate
// plugin shape: a tool.execute.before hook that records the tool call.
import { appendFileSync } from "node:fs";

export const EdictumProbe = async () => {
  return {
    "tool.execute.before": async (input: any, output: any) => {
      appendFileSync(
        "$events",
        JSON.stringify({ tool: input.tool, args: output.args }) + "\n"
      );
    },
  };
};
EOF
  fi

  (cd "$dir" && run_cli_probe "$host" \
    opencode run "Run exactly this shell command and reply with its output: echo edictum-probe-$host")

  check_hook_evidence "$host" "$events"
}

# ---------------------------------------------------------------------------

{
  echo "edictum real-host harness skeleton"
  echo "time (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -a)"
  echo "break mode: ${REALHOST_BREAK_HOOK:-0}"
  echo "log dir: $LOG_DIR"
} > "$LOG_DIR/summary.txt"
cat "$LOG_DIR/summary.txt"

run_claude_code
run_copilot
run_opencode

log ""
log "=== summary ==="
if [ -n "$FAILURES" ]; then
  log "RED run. Failures:$FAILURES"
  { echo ""; echo "RED run. Failures:$FAILURES"; } >> "$LOG_DIR/summary.txt"
  exit 1
fi
log "GREEN run: all three hosts drove a PreToolUse seam with hook evidence recorded."
echo "GREEN run: all three hosts drove a PreToolUse seam with hook evidence recorded." >> "$LOG_DIR/summary.txt"
exit 0
