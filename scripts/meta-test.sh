#!/usr/bin/env bash
# Meta-test: use sigil to manage a tmux session end-to-end.
#
# Proves sigil can create, start, send a command, read output, and stop
# a session — no API keys required, just tmux + echo.
#
# Usage: scripts/meta-test.sh

set -euo pipefail

TITLE="meta-test-$$"

# ── Preflight ────────────────────────────────────────────────────────
if ! command -v sigil &>/dev/null; then
    echo "error: 'sigil' not found on PATH."
    echo "Install with: cargo install --path crates/sigil-cli"
    exit 1
fi

if ! command -v tmux &>/dev/null; then
    echo "error: 'tmux' not found."
    exit 1
fi

# ── Setup ────────────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'sigil session stop "$TITLE" 2>/dev/null; sigil session remove "$TITLE" 2>/dev/null; rm -rf "$WORK_DIR"' EXIT

echo "==> Work dir: $WORK_DIR"
echo "==> Session:  $TITLE"

# ── Create ───────────────────────────────────────────────────────────
echo "--- create ---"
sigil session create "$WORK_DIR" -t "$TITLE"

# ── Start ────────────────────────────────────────────────────────────
echo "--- start ---"
sigil session start "$TITLE"

# ── Send ─────────────────────────────────────────────────────────────
echo "--- send ---"
MARKER="hello-from-sigil-meta-$$"
sigil session send "$TITLE" "echo $MARKER"

# Give tmux a moment to process keystrokes.
sleep 1

# ── Output ───────────────────────────────────────────────────────────
echo "--- output ---"
OUTPUT="$(sigil session output "$TITLE" -q)"
echo "$OUTPUT"

# ── Verify ───────────────────────────────────────────────────────────
if echo "$OUTPUT" | grep -q "$MARKER"; then
    echo "✓ marker '$MARKER' found in output"
else
    echo "✗ marker '$MARKER' NOT found in output"
    exit 1
fi

# ── Stop ─────────────────────────────────────────────────────────────
echo "--- stop ---"
sigil session stop "$TITLE"

# ── Remove ───────────────────────────────────────────────────────────
echo "--- remove ---"
sigil session remove "$TITLE"

# Disable the trap's cleanup since we already removed.
trap 'rm -rf "$WORK_DIR"' EXIT

echo ""
echo "==> Meta-test passed."
