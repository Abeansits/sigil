# Apple Containers PoC Validation

**Date:** 2026-04-07  
**macOS:** 26.4 (Darwin 25.4.0, arm64)  
**CLI:** `container` v0.11.0 — [github.com/apple/container](https://github.com/apple/container)  
**Test image:** `node:22-slim` (linux/arm64)

## Summary

Apple Containers provide strong primitives for sigil's container runtime backend. Six of eight checklist items pass natively. Domain-level network filtering is the main gap and requires a proxy-based fallback.

| # | Primitive | Result | Notes |
|---|-----------|--------|-------|
| 1 | RW volume mount (VirtioFS) | PASS | `-v` and `--mount type=bind` both work |
| 2 | RO volume mount | PASS | `--mount type=bind,...,readonly` rejects writes |
| 3 | Unix socket publishing | PASS | `--publish-socket host:container` works bidirectionally |
| 4 | Domain-level network allowlist | FAIL | Only binary: full internet or `--internal` (none) |
| 5 | Forward proxy fallback | DESIGNED | See [Proxy Fallback Design](#5-forward-proxy-fallback-design) |
| 6 | Env var injection | PASS | `-e KEY=VALUE` and `--env-file` both supported |
| 7 | Process isolation | PASS | Container sees only its own PIDs |
| 8 | VirtioFS latency | PASS | 0.6ms median (file), 0.2ms median (socket) |

## Detailed Results

### 1. RW Volume Mount (VirtioFS)

**Command:**
```bash
container run --rm -v /tmp/test:/mnt/shared node:22-slim \
  sh -c 'cat /mnt/shared/host-file.txt && echo "from container" > /mnt/shared/new.txt'
```

**Result:** PASS
- Host file readable inside container
- Container-created files immediately visible on host
- File ownership maps to the host user (uid preserved)
- Both `-v src:dst` shorthand and `--mount type=bind,source=...,target=...` work

**Sigil implications:** Worktree directories can be mounted directly. The agent sees the repo at a known path and changes are immediately visible for conductor heartbeat scans.

### 2. RO Volume Mount

**Command:**
```bash
container run -d --name ro-test \
  --mount type=bind,source=/tmp/test,target=/mnt/shared,readonly \
  node:22-slim sleep 300
container exec ro-test cat /mnt/shared/host-file.txt    # succeeds
container exec ro-test sh -c 'echo x > /mnt/shared/f'   # fails
```

**Result:** PASS
- Reads succeed
- Writes produce: `sh: 1: cannot create /mnt/shared/f: Read-only file system`
- Exit code 2 on write attempt

**Sigil implications:** Config files, templates, and read-only context can be mounted separately from the writable worktree. Supports least-privilege mount strategy.

### 3. Unix Socket Publishing

**Command:**
```bash
container run -d --name sock-test \
  --publish-socket /tmp/sigil.sock:/tmp/sigil.sock \
  node:22-slim node -e "
    const net = require('net');
    const s = net.createServer(c => c.on('data', d => c.write('echo: '+d)));
    s.listen('/tmp/sigil.sock');
  "
# From host:
echo "hello" | nc -U /tmp/sigil.sock   # Returns: echo: hello
```

**Result:** PASS
- Socket appears on host filesystem as expected path
- Bidirectional communication works (host sends, container responds)
- Socket is created with host user permissions
- Multiple concurrent connections work

**Sigil implications:** This is the primary IPC mechanism for the MCP approval server. The host-side sigil conductor can connect to the container's approval socket without port forwarding or TCP. Clean, fast, no network stack involved.

### 4. Domain-Level Network Allowlist

**Investigation:**
- `container network create` supports `--internal` (host-only), `--subnet`, and MTU options
- No firewall rules, ACL, or domain filtering in CLI, API, or network plugins
- `--internal` network blocks both DNS and direct IP connectivity (confirmed by test)
- Default network allows unrestricted internet access
- No iptables/nftables available inside the container
- Network plugins ([apple/container#1151](https://github.com/apple/container/pull/1151)) are for
  alternative L2 backends, not per-container traffic filtering
- The underlying vmnet framework provides L2 networking; domain filtering is an L7 concern
  and is unlikely to be added upstream

**Result:** FAIL — binary choice only
- `--internal`: zero internet access (DNS and TCP both blocked)
- default network: full internet access, no filtering

**What this means for sigil:** The agent container cannot natively restrict network to "only api.anthropic.com and github.com". This is the most significant gap. See fallback design below.

### 5. Forward Proxy Fallback Design

Since Apple Containers don't support domain-level filtering, we need a proxy running on the host (or in a sidecar) that the container routes all traffic through. The proxy enforces the allowlist.

#### Architecture

```text
Container (--internal network)
  |
  |-- all HTTP/HTTPS traffic -->  [unix socket] --> Host-side proxy
  |                                                     |
  |                                                     +--> allowlist check
  |                                                     |      |
  |                                                     |      +-- ALLOW --> forward to internet
  |                                                     |      +-- DENY  --> 403 response
  |                                                     |
  +-- published socket for MCP/IPC (separate socket)
```

#### Option A: Squid Forward Proxy

Squid supports domain-based ACLs natively and handles CONNECT tunneling for HTTPS.

**Host-side squid config:**
```text
# /etc/sigil/squid-<session-id>.conf
acl sigil_allowed dstdomain .anthropic.com .github.com .npmjs.org
http_access allow sigil_allowed
http_access deny all

# Listen on a Unix socket instead of TCP
http_port /tmp/sigil-proxy-<session-id>.sock
```

**Container launch:**
```bash
container run -d --name agent-session \
  --network sigil-internal \
  --publish-socket /tmp/sigil-proxy.sock:/tmp/proxy.sock \
  --publish-socket /tmp/sigil-mcp.sock:/tmp/mcp.sock \
  -e HTTP_PROXY=http://unix:/tmp/proxy.sock \
  -e HTTPS_PROXY=http://unix:/tmp/proxy.sock \
  -e NO_PROXY=localhost,127.0.0.1 \
  -v /path/to/worktree:/workspace \
  sigil-agent:latest
```

**Trade-offs:**
- Pro: Domain filtering for both HTTP and HTTPS (via CONNECT)
- Pro: Audit log of all outbound requests
- Pro: Per-session proxy with per-session allowlist
- Con: Requires squid installed on host (or in a sidecar container)
- Con: HTTPS inspection only sees domain (SNI), not full URL — which is fine for allowlisting

#### Option B: nginx Stream Proxy (Simpler, Less Flexible)

```text
stream {
    map $ssl_preread_server_name $upstream {
        api.anthropic.com    upstream_allow;
        github.com           upstream_allow;
        default              upstream_deny;
    }
    upstream upstream_allow { server 0.0.0.1:443; }  # passthrough
    upstream upstream_deny  { server 127.0.0.1:1; }  # reject
    server {
        listen /tmp/sigil-proxy.sock;
        ssl_preread on;
        proxy_pass $upstream;
    }
}
```

**Trade-offs:**
- Pro: Simpler config, nginx likely already available
- Con: Only works for TLS (SNI-based), no HTTP filtering
- Con: Less mature Unix socket listener support

#### Option C: Custom Rust Proxy in sigil-runtime (Recommended)

A lightweight CONNECT-only proxy built into `sigil-runtime` that:
1. Listens on a Unix socket
2. Accepts CONNECT requests
3. Checks the target domain against a `Vec<String>` allowlist
4. Either tunnels or rejects

**Trade-offs:**
- Pro: Zero external dependencies, ships with sigil
- Pro: Integrates with audit logging natively
- Pro: Allowlist is part of the session config, not a separate file
- Con: More code to write and maintain
- Con: Must handle both HTTP and HTTPS CONNECT correctly

#### Recommendation

**Start with Option C** (custom Rust proxy). The allowlist is small (typically 3-5 domains), the proxy logic is straightforward (just CONNECT tunneling with domain check), and it avoids requiring squid on every host. It also integrates naturally with the audit trail — every outbound connection attempt is an auditable event.

If Option C proves insufficient (e.g., need full HTTP rewriting or caching), fall back to Option A (squid) with a managed config file.

### 6. Environment Variable Injection

**Command:**
```bash
container run -d --name env-test \
  -e SIGIL_SESSION_ID=test-session-42 \
  -e SIGIL_TRUST_ZONE=AgentRuntime \
  -e API_KEY=secret123 \
  node:22-slim sleep 300
container exec env-test env | grep SIGIL
```

**Result:** PASS
- All `-e KEY=VALUE` vars visible inside container
- `--env-file` also supported for bulk injection
- Env vars persist across `container exec` calls
- Key-only form (`-e KEY`) inherits from host environment

**Sigil implications:** Session ID, trust zone, audit config, and API keys can all be injected at launch time. The `--env-file` option is useful for secrets that shouldn't appear in process arguments.

### 7. Process Isolation

**Test:**
```bash
container exec env-test sh -c 'for pid in /proc/[0-9]*; do
  echo "PID $(basename $pid): $(cat $pid/cmdline 2>/dev/null | tr "\0" " ")"
done'
```

**Result:** PASS
```
PID 1: sleep 300
PID 6: sh -c for pid in /proc/[0-9]*; ...
```

- Container PID namespace is fully isolated
- PID 1 is the container's init process, not the host's
- No host processes visible
- `/proc` is container-scoped

**Sigil implications:** A compromised agent cannot inspect host processes, read other sessions' memory, or signal host processes. This is the baseline isolation guarantee that makes containers valuable over bare tmux.

### 8. VirtioFS Latency for File-Based IPC

#### File I/O Benchmark (container write + read, 100 iterations)

| Metric | Value |
|--------|-------|
| Min | 0.410 ms |
| Median | 0.615 ms |
| P95 | 0.856 ms |
| P99 | 1.721 ms |
| Max | 1.721 ms |
| Mean | 0.631 ms |

#### Unix Socket IPC Benchmark (host -> container -> host round-trip, 100 iterations)

| Metric | Value |
|--------|-------|
| Min | 0.126 ms |
| Median | 0.179 ms |
| P95 | 1.132 ms |
| P99 | 3.799 ms |
| Max | 3.799 ms |
| Mean | 0.318 ms |

**Analysis:**
- VirtioFS file I/O: ~0.6ms median — perfectly adequate for file-based IPC and worktree operations
- Unix socket IPC: ~0.2ms median — excellent for request/response patterns (MCP, approval protocol)
- Both are well within the latency budget for agent orchestration (heartbeat intervals are seconds, not milliseconds)
- Socket IPC is ~3x faster than file-based IPC — prefer sockets for the approval protocol

**Sigil implications:** VirtioFS adds negligible overhead to worktree file operations. The agent's file reads/writes will feel native. Socket-based IPC is the right choice for the MCP approval server given its lower latency and natural request/response semantics.

## Gaps and Risks

### Critical Gap: Domain-Level Network Filtering

This is the only hard gap. The current options are:
1. **Full isolation** (`--internal`): agent can't reach any API — unusable for Claude Code
2. **Full access** (default): agent can reach anything — defeats the purpose of sandboxing
3. **Proxy fallback**: adds complexity but solves the problem

The proxy approach (Option C above) is the recommended path forward.

### Minor Gaps

- **Container stop timeout:** `container stop` occasionally times out with an XPC error. `container kill` works reliably as a fallback. The conductor should try `stop` first, then `kill` after a timeout.
- **No dynamic resource adjustment:** `--cpus` and `--memory` are set at launch only. This is fine — sessions don't need runtime resource changes.
- **Image build required:** Need to build a `sigil-agent` image with Claude Code, git, and the proxy client pre-installed. `container build` supports Dockerfiles.

## Prerequisites

- **macOS 26.0+** (Tahoe) — required for full networking support (multiple networks, container-to-container communication)
- **Apple Silicon** (arm64) — confirmed working
- **Xcode** installed (provides the Containerization framework)
- `container system start` must be run before first use
- Install: `brew install container`

## Next Steps

1. Build a minimal `sigil-agent` container image (Dockerfile with Claude Code + git + node)
2. Implement the Rust forward proxy in `sigil-runtime` (Option C)
3. Add `ContainerRuntime` trait implementation alongside `TmuxRuntime`
4. Wire socket-based IPC for the MCP approval protocol
5. Add container lifecycle to conductor heartbeat scans
