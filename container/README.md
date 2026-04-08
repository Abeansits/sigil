# sigil-agent Container Image

Minimal container image for running AI coding agents (Claude Code, Codex CLI) inside Apple Containers with domain-filtered network access.

## Prerequisites

- macOS 26.0+ (Tahoe) on Apple Silicon
- `container` CLI installed (`brew install container`)
- `container system start` has been run

## Build

```bash
container build -t sigil-agent:latest container/
```

Or use the build script:

```bash
scripts/build-agent-image.sh
```

## What's Inside

| Component       | Purpose                              |
|-----------------|--------------------------------------|
| Node.js 22      | Runtime for Claude Code and Codex    |
| git             | Clone repos, commit changes          |
| curl            | Health checks, API fallback          |
| python3         | Required by some tool chains         |
| build-essential | Native npm module compilation        |
| Claude Code CLI | `claude` — Anthropic's coding agent  |
| Codex CLI       | `codex` — OpenAI's coding agent      |

## Runtime Usage

The conductor launches containers with socket mounts and environment injection:

```bash
container run -d --name agent-session \
  --network sigil-internal \
  --publish-socket /tmp/sigil-proxy.sock:/tmp/proxy.sock \
  --publish-socket /tmp/sigil-mcp.sock:/tmp/mcp.sock \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e SIGIL_SESSION_ID=my-session \
  -v /path/to/worktree:/workspace \
  sigil-agent:latest
```

Then interact via exec:

```bash
container exec agent-session claude --print "Explain this codebase"
```

## Secrets

**No secrets are baked into the image.** API keys and tokens are injected at runtime via `-e` flags or `--env-file`.

## Network

The image defaults to routing traffic through a Unix socket proxy at `/tmp/proxy.sock`. The host-side sigil proxy performs domain-level filtering (see `docs/CONTAINER-POC.md` section 5). Containers should be launched on an `--internal` network so the proxy is the only path to the internet.

## Smoke Test

```bash
scripts/test-agent-image.sh
```

Verifies that Node.js, git, Claude Code, and Codex are correctly installed.
