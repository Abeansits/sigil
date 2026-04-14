# sigil

```
     _       _ _
 ___(_) __ _(_) |
/ __| |/ _` | | |
\__ \ | (_| | | |
|___/_|\__, |_|_|
       |___/
```

A security-first Rust workspace for managing AI agent sessions. It replaces the older Go + Python split with one typed, testable workspace built around policy checks, audit logging, and sandboxed orchestration via tmux or Apple Containers.

## The Name

*Sigil* comes from Latin *sigillum* — a seal of authority. In sigil, every orchestrated action carries typed authority through `ActionRequest`, and every decision is sealed into an HMAC-chained audit trail. The name reflects what the tool enforces: nothing runs without a seal of approval.

## Getting Started

### Install

```bash
git clone https://github.com/Abeansits/sigil.git
cd sigil
cargo install --path crates/sigil-cli
```

Requires Rust 1.85+. The binary is called `sigil`.

### Your First Session

```bash
# Create a session pointing at a project directory
sigil session create ~/Projects/my-app --title my-session

# Start the tmux session
sigil session start my-session

# Send a message to the agent
sigil session send my-session "Summarize this codebase"

# Read the agent's output
sigil session output my-session

# Stop when done
sigil session stop my-session
```

Or do it all in one command:

```bash
sigil session launch ~/Projects/my-app \
  --title my-session \
  --tool claude \
  --message "Summarize this codebase"
```

### Status and Conductor

```bash
# Quick system overview
sigil status

# Run the conductor (heartbeat, reconciliation, grant cleanup)
sigil conductor --interval 30
```

### Bridge Setup

Connect Telegram and/or Slack for remote session control:

```bash
# Required environment variables
export SIGIL_TELEGRAM_TOKEN="your-bot-token"
export SIGIL_SLACK_APP_TOKEN="xapp-..."
export SIGIL_SLACK_BOT_TOKEN="xoxb-..."

# Run a single bridge
sigil bridge telegram
sigil bridge slack

# Run all bridges concurrently
sigil bridge all
```

Bridge commands: `/status`, `/sessions`, `/check`, `/send <session> <message>`.

### Running as a Service (macOS)

Run the conductor + Telegram bridge as a persistent launchd service that starts at login and restarts on crash.

**Store your token in Keychain** (one-time):

```bash
security add-generic-password -s sigil-telegram-token -a $USER -w "your-bot-token"
```

**Install:**

```bash
scripts/install-service.sh
```

The install script creates a wrapper at `~/.sigil/sigil-run.sh` that loads the token from Keychain at launch, installs the plist to `~/Library/LaunchAgents/`, and starts the service.

**Check status / logs:**

```bash
launchctl print gui/$(id -u)/com.sigil.conductor
tail -f ~/.sigil/logs/sigil.log
```

**Uninstall:**

```bash
scripts/uninstall-service.sh
```

### Audit Verification

Every session action is logged to an HMAC-chained audit trail:

```bash
# Verify the audit log chain integrity
sigil audit verify

# Optionally set a custom HMAC key (defaults to a dev key)
export SIGIL_AUDIT_KEY="your-secret-key"
```

### Container Sessions

For sandboxed sessions in Apple Container VMs (macOS 26.0+, Apple Silicon):

```bash
# Build the agent image (one-time)
scripts/build-agent-image.sh

# Create and run a container session (requires --features container)
sigil --runtime container session create ~/Projects/my-app --title sandboxed
sigil --runtime container session start sandboxed

# Or set via env var
export SIGIL_RUNTIME=container
sigil session create ~/Projects/my-app --title sandboxed
```

Container sessions support domain-filtered networking and MCP-based policy mediation. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full container runtime flow.

## Workspace

```text
sigil-cli         `sigil` binary, clap commands, audit wiring
sigil-conductor   Heartbeat loop, reconciliation, bridge message handling
sigil-bridge      Telegram/Slack parsing, identity resolution, routing, live bridge loops
sigil-mcp         Host-side MCP server for policy-mediated agent actions
sigil-runtime     tmux + container runtimes, domain proxy, MCP socket, tool adapters, worktree manager
sigil-store       SQLite persistence for sessions and approval grants
sigil-policy      Trust-zone checks, tier evaluation, normalization, fatigue guard, grant model
sigil-audit       HMAC-chained JSONL audit writer and verifier
sigil-core        Action protocol, origins, principals, trust model, trait ports
```

The workspace is a 9-crate DAG with `sigil-core` at the bottom and no internal dependency cycles.

## Design

- `ActionRequest` is the typed authority protocol for orchestrated actions.
- Terminal parsing is observability-only; `ToolAdapter` emits `AgentSignal`, not authority.
- Trust zones are `Ingress`, `ControlPlane`, `AgentRuntime`, and `HostPrivileged`.
- Audit events are written as append-only HMAC-chained JSONL entries.
- Approval grants have a real domain model, SQLite storage, and are consulted by the policy evaluator.
- `FatigueGuard` is wired into the approval flow.
- Two runtime backends: `TmuxRuntime` (default) and `ContainerRuntime` (Apple Containers, behind `container` feature).
- Container sessions get domain-filtered networking via a host-side forward proxy and policy-mediated agent IPC via MCP over Unix sockets.
- Host-side MCP server (`sigil-mcp`) provides policy-mediated tool access for container agents.

## Build and Verify

```bash
cargo build --release     # current macOS arm64 build: 5.7M
cargo test               # 443 tests (includes proptest property-based tests)
cargo clippy --workspace --all-targets -- -D warnings
```

Rust 1.85+ is required. The release profile uses thin LTO and `codegen-units = 1`.

## Status

The workspace has working session lifecycle commands, status reporting, worktree management, tmux and container runtime backends, domain-filtered container networking, MCP-based policy-mediated agent IPC, tmux reconciliation, audit logging with CLI verification, policy evaluation with grant-store integration and fatigue guarding, bridge CLI commands for Slack and Telegram, an agent container image, and property-based tests across core invariants.

Remaining gaps:

- audit key management still uses env var or dev fallback, not Keychain-backed storage
- content sanitization pipeline for fetched web/media inputs is not implemented

## Docs

- [Architecture](docs/ARCHITECTURE.md) — workspace structure, dependency graph, runtime flow, container runtime
- [Feature Audit](docs/FEATURE-AUDIT.md) — current status of the feature set carried over from agent-deck
- [Rewrite Proposal](docs/REWRITE-PROPOSAL.md) — proposal history plus what has and has not landed
- [Security Plan](docs/SECURITY-PLAN.md) — current security controls and remaining hardening work
- [Use Cases](docs/USE-CASES.md) — CLI and library walkthroughs aligned to the current command surface
- [Agent Traps Defense](docs/AGENT-TRAPS-DEFENSE.md) — threat-model notes for current and planned defenses
- [Container PoC](docs/CONTAINER-POC.md) — Apple Containers validation and PoC results
- [Stego Defense](docs/STEGO-DEFENSE.md) — steganography hardening notes and future work
- [Agent Image](container/README.md) — Dockerfile and build instructions for the container agent image

## License

MIT
