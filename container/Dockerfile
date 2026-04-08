# sigil-agent container image
#
# Minimal environment for running AI coding agents (Claude Code, Codex)
# inside Apple Containers. Network traffic routes through a host-side
# domain-filtering proxy via a published Unix socket.
#
# Build:  container build -t sigil-agent:latest container/
# Run:    container run --rm sigil-agent:latest node --version

FROM node:22-slim

LABEL org.opencontainers.image.title="sigil-agent" \
      org.opencontainers.image.description="Sandboxed coding-agent runtime for sigil" \
      org.opencontainers.image.source="https://github.com/Abeansits/sigil"

# Install system dependencies in a single layer.
# git          — agent needs to clone/commit
# curl         — health checks, API fallback
# python3      — some tool chains require it
# build-essential — native npm modules (node-gyp)
# ca-certificates — TLS verification through the proxy
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       git \
       curl \
       python3 \
       build-essential \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI and Codex CLI globally.
RUN npm install -g @anthropic-ai/claude-code @openai/codex \
    && npm cache clean --force

# Workspace directory where the worktree is mounted at runtime.
RUN mkdir -p /workspace
WORKDIR /workspace

# Proxy environment — overridden at runtime via -e flags, but these
# defaults document the expected socket paths from the PoC.
ENV HTTP_PROXY=http://unix:/tmp/proxy.sock
ENV HTTPS_PROXY=http://unix:/tmp/proxy.sock
ENV NO_PROXY=localhost,127.0.0.1

# The conductor sends commands via `container exec`; the container
# itself just stays alive.
ENTRYPOINT ["sleep", "infinity"]
