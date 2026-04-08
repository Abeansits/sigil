#!/usr/bin/env bash
# Smoke-test the sigil-agent container image.
#
# Usage: scripts/test-agent-image.sh [tag]
#   tag  — image tag to test (default: sigil-agent:latest)

set -euo pipefail

TAG="${1:-sigil-agent:latest}"
PASSED=0
FAILED=0

run_check() {
    local label="$1"
    shift
    printf "  %-30s" "$label"
    if output=$( container run --rm "$TAG" "$@" 2>&1 ); then
        echo "PASS  ($output)"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        echo "    $output" | head -3
        FAILED=$((FAILED + 1))
    fi
}

echo "Smoke-testing image: $TAG"
echo ""

run_check "Node.js"        node --version
run_check "git"            git --version
run_check "Claude Code"    claude --version
run_check "Codex"          which codex

echo ""
echo "Results: $PASSED passed, $FAILED failed"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
