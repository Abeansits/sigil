#!/usr/bin/env bash
# Build the sigil-agent container image.
#
# Usage: scripts/build-agent-image.sh [tag]
#   tag  — image tag (default: sigil-agent:latest)

set -euo pipefail

TAG="${1:-sigil-agent:latest}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTEXT_DIR="$REPO_ROOT/container"

# ── Preflight ────────────────────────────────────────────────────────
if ! command -v container &>/dev/null; then
    echo "error: 'container' CLI not found."
    echo "Install it with:  brew install container"
    echo "Then run:          container system start"
    exit 1
fi

if [ ! -f "$CONTEXT_DIR/Dockerfile" ]; then
    echo "error: Dockerfile not found at $CONTEXT_DIR/Dockerfile"
    exit 1
fi

# ── Build ────────────────────────────────────────────────────────────
echo "Building $TAG from $CONTEXT_DIR ..."
container build -t "$TAG" "$CONTEXT_DIR"

# ── Verify ───────────────────────────────────────────────────────────
if container image list 2>/dev/null | grep -q "${TAG%%:*}"; then
    echo ""
    echo "Image built successfully: $TAG"
    container image list 2>/dev/null | head -1
    container image list 2>/dev/null | grep "${TAG%%:*}"
else
    echo "warning: could not verify image in 'container image list'."
    echo "The build command exited successfully — the image may still be usable."
fi
