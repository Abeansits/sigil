# Agent-Ops: Rust Rewrite Proposal

**Status:** Final. 2 rounds of Ting review (3 models x 2 rounds), Codex consultation, Vigil analysis.
**Date:** 2026-04-06

## Pre-Build Checklist (Do Before Writing Rust)

These were identified as build-blockers by all three reviewers across two rounds. Complete in order.

### 1. Apple Container PoC (1 day)
Validate every container primitive we depend on:
- [ ] Mount directory read-write via VirtioFS/Shared Folders
- [ ] Mount directory read-only
- [ ] Publish Unix socket from container to host
- [ ] Apply domain-level network allowlist (not just port-level)
- [ ] If no domain filtering: design local forward proxy fallback
- [ ] Inject environment variables at container launch
- [ ] Verify process isolation (container process can't see host processes)
- [ ] Measure VirtioFS latency for file-based IPC
- [ ] Document results and any gaps

### 2. MCP-IPC Schema Design
Design the host-side MCP server that agents use for structured requests:
- [ ] Define MCP tool schema: `request_approval({ action: "ReadHostFile", path: "/etc/hosts" })`
- [ ] This is the SOLE authority path — terminal parsing never grants authority
- [ ] Co-design with the capability model (Action enum effect classes)
- [ ] Define how MCP server routes through ops-policy

### 3. IPC Protocol Spec (1 page)
For file-based IPC between container agent and host conductor:
- [ ] Per-session private directory with strict ownership (0700)
- [ ] Write-temp then atomic rename
- [ ] Monotonic sequence numbers and request IDs
- [ ] State machine: pending → accepted/denied → executed/expired
- [ ] Replay cache persisted across restart
- [ ] Garbage collection and tombstoning
- [ ] Bounded schema — no natural-language authority

### 4. Effect-Class Action Split
- [ ] Split T3 into: ReadHostFile, WriteHostFile, ExecuteHostCommand, ModifyGitState, ExternalNetworkWrite, ServiceControl
- [ ] Capabilities are the internal model; tiers are UX presets
- [ ] Design workflow-level approval bundles (e.g., "test and deploy" = RunTest + GitPush)

### 5. HMAC Key Lifecycle
- [ ] Store key in macOS Keychain with kSecAttrAccessControl (user presence at startup)
- [ ] Retrieve via security-framework crate
- [ ] Build separate read-only audit verification tool
- [ ] Define rotation policy

### 6. Principal Model Design
- [ ] Define Principal struct: identity, auth strength, platform binding, trust posture, revocation
- [ ] Map ActionOrigin → Principal → permissions (not ActionOrigin → permissions directly)
- [ ] Slack: bind to workspace ID, restrict channel types

---

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AGENT-OPS (Rust binary)                      │
│                                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │ ops-cli  │    │ops-bridge│    │   ops-   │    │   ops-   │      │
│  │          │    │          │    │conductor │    │ runtime  │      │
│  │ Commands │    │ Telegram │    │          │    │          │      │
│  │ JSON out │    │ Slack    │    │Heartbeat │    │ tmux +   │      │
│  └────┬─────┘    └────┬─────┘    │AutoResp  │    │container │      │
│       │               │         │Escalate  │    │backends  │      │
│       │               │         └────┬─────┘    └────┬─────┘      │
│       │               │              │               │            │
│       ▼               ▼              ▼               ▼            │
│  ┌─────────────────────────────────────────────────────────┐      │
│  │                      ops-policy                         │      │
│  │  Action enum + ActionOrigin + Trust Zones + Tier eval   │      │
│  │  Approval gateway + Grant checking + Input normalization│      │
│  └────────────────────────┬────────────────────────────────┘      │
│                           │                                       │
│  ┌────────────┐    ┌──────┴──────┐                                │
│  │ ops-audit  │    │  ops-store  │                                │
│  │ JSONL+HMAC │    │   SQLite    │                                │
│  └────────────┘    └─────────────┘                                │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐      │
│  │                      ops-core                           │      │
│  │  Action, ActionOrigin, traits, domain models            │      │
│  └─────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

## Message Flow (Slack → Agent → Host)

```
Paul (Slack)
  │
  ▼
┌──────────────────────────────────┐
│ ops-bridge: Slack adapter        │
│ 1. Verify sender allowlist       │
│ 2. Rate limit check              │
│ 3. Sanitize input (strip-invis)  │
│ 4. Set ActionOrigin::BridgeSlack │
│ 5. Map to Action enum            │
└──────────────┬───────────────────┘
               │ ActionRequest { action, origin: BridgeSlack }
               ▼
┌──────────────────────────────────┐
│ ops-policy: evaluate             │
│ 1. Check trust zone (Z0 → Z1)   │
│ 2. Check tier ceiling (T1 max)   │
│ 3. Check approval grants         │
│ 4. Log to audit trail            │
│ ALLOW or DENY                    │
└──────────────┬───────────────────┘
               │ if ALLOW
               ▼
┌──────────────────────────────────┐
│ ops-conductor                    │
│ Route to correct session         │
│ Translate Action → agent message │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│ ops-container (Apple Container)  │
│ ┌──────────────────────────────┐ │
│ │ Claude Code session          │ │
│ │ • /workspace/project (rw)   │ │
│ │ • /workspace/scratch (rw)   │ │
│ │ • No ~/.ssh, ~/.aws         │ │
│ │ • Network: allowlist only   │ │
│ └──────────────────────────────┘ │
│                                  │
│ Agent wants privileged op?       │
│ → Request via Unix socket ───────┤
└──────────────────────────────────┘
               │ approval request
               ▼
┌──────────────────────────────────┐
│ ops-policy: approval gateway     │
│ 1. Check existing grants         │
│ 2. No grant? → Notify Sebastian  │
│ 3. Approved → Mint TTL grant     │
│ 4. Timeout → Auto-deny           │
└──────────────────────────────────┘
```

## Vs (Paul's Agent) — Container Profile

```
┌─ Apple Container: "vs-daydream" ─────────────────────────────────┐
│                                                                   │
│  Claude Code (or Codex)                                          │
│                                                                   │
│  MOUNTS:                                                         │
│  ├─ /workspace/project ←→ ~/Projects/DayDream-Projects/ (rw)    │
│  ├─ /workspace/scratch ←→ persistent scratchpad (rw)             │
│  ├─ /workspace/fonts   ←→ ~/Library/Fonts/ (ro)                  │
│  ├─ /home/agent/.claude ←→ Claude config (ro)                    │
│  └─ /run/mcp/*.sock   ←→ MCP server sockets (ro)                │
│                                                                   │
│  ENV (injected from Keychain at launch):                         │
│  ├─ RUNWAY_API_KEY                                               │
│  ├─ ELEVENLABS_API_KEY                                           │
│  ├─ IDEOGRAM_API_KEY                                             │
│  ├─ VERCEL_TOKEN                                                 │
│  ├─ META_ACCESS_TOKEN                                            │
│  └─ SCRAPECREATORS_KEY                                           │
│                                                                   │
│  NETWORK ALLOWLIST:                                              │
│  ├─ api.anthropic.com        (Claude API)                        │
│  ├─ api.ideogram.ai          (image gen)                         │
│  ├─ api.runwayml.com         (video gen)                         │
│  ├─ api.elevenlabs.io        (voice/audio)                       │
│  ├─ graph.facebook.com       (Meta Ads API)                      │
│  ├─ api.vercel.com           (deployment)                        │
│  ├─ github.com               (git push)                          │
│  ├─ registry.npmjs.org       (npm install)                       │
│  └─ scrapecreators.com       (social research)                   │
│                                                                   │
│  BLOCKED:                                                        │
│  ├─ ~/.ssh, ~/.aws, ~/.gnupg, ~/.config/gcloud                  │
│  ├─ All other sessions' directories                              │
│  ├─ Host shell / host filesystem (except mounts)                 │
│  ├─ Local LAN (192.168.x.x, 10.x.x.x)                          │
│  └─ Any domain not in allowlist                                  │
│                                                                   │
│  WHAT PAUL CAN STILL DO (everything he does today):              │
│  ✓ Image generation (Ideogram + Pillow text overlay)             │
│  ✓ Video production (Runway + ElevenLabs + ffmpeg)               │
│  ✓ Social media research (ScrapeCreators API)                    │
│  ✓ Meta Ads management (create, pause, optimize campaigns)       │
│  ✓ Client proposal deployment (Vercel)                           │
│  ✓ Content review and iteration                                  │
│  ✓ Brainstorming and strategy                                    │
│  ✓ Git commit and push to DayDream repos                         │
│                                                                   │
│  WHAT PAUL LOSES (things he never needed):                       │
│  ✗ Reading files outside DayDream-Projects                       │
│  ✗ Shell access to host machine                                  │
│  ✗ Access to other agent sessions                                │
│  ✗ Installing packages on host                                   │
│  ✗ Network access to unlisted domains                            │
└───────────────────────────────────────────────────────────────────┘
```

## The Pitch

One Rust binary replaces agent-deck (Go) + bridge.py (Python). Security baked in from day one. No npm/pip in the dependency chain. ~50 features we actually use, not 120 we don't. Apple Containers for sandboxing untrusted agents.

---

## Workspace Layout

```
agent-ops/
  Cargo.toml (workspace)
  crates/
    ops-cli/          # clap commands, JSON output, exit codes
    ops-core/         # domain models, Action enum, ActionOrigin, trait ports
    ops-policy/       # trust zones, tier evaluation, grant checking, input sanitization
    ops-audit/        # append-only JSONL writer, HMAC chain, replay tool
    ops-store/        # SQLite + migrations + outbox tables
    ops-runtime/      # SessionRuntime trait, ToolAdapter trait, tmux backend, hooks
    ops-bridge/       # Telegram + Slack adapters, identity resolution, routing
    ops-conductor/    # heartbeat loop, escalation, child coordination, budget guard
```

8 crates (container backend merged into ops-runtime, feature-gated).

### Dependency Graph (DAG, no cycles)

```
ops-cli → ops-conductor, ops-bridge, ops-runtime, ops-store, ops-policy, ops-core
ops-conductor → ops-runtime, ops-store, ops-policy, ops-audit, ops-core
ops-bridge → ops-store, ops-policy, ops-audit, ops-core
ops-runtime → ops-store, ops-policy, ops-core
ops-store → ops-core
ops-policy → ops-audit, ops-core
ops-audit → ops-core
ops-core → (no internal deps)
```

Container backend is feature-gated in ops-runtime: `[features] container = ["apple-container-deps"]`.

Bridge and conductor never depend on each other directly. Both use routing traits defined in `ops-core` (`trait MessageSink`, `trait MessageSource`, `trait ActionRouter`).

---

## The Action Enum (Core Security Primitive)

Every operation in the system is an `Action`. No string commands cross module boundaries. The Action enum is the sole authority-bearing protocol.

```rust
pub struct ActionRequest {
    pub id: Ulid,
    pub action: Action,
    pub origin: ActionOrigin,
    pub timestamp: OffsetDateTime,
}

pub enum ActionOrigin {
    LocalCli,
    BridgeTelegram { user_id: String },
    BridgeSlack { user_id: String, channel_id: String },
    AgentGenerated { session_id: Ulid },
    SystemHeartbeat,
    HumanApproved { approver: String, original_origin: Box<ActionOrigin> },
}

pub enum Action {
    // T0 — Read (anyone)
    ListSessions,
    GetSessionStatus { session_id: Ulid },
    ReadSessionOutput { session_id: Ulid },
    ListGroups,
    GetSystemStatus,

    // T1 — Operate (Sebastian, Paul)
    CreateSession { path: PathBuf, title: String, group: Option<String>, tool: ToolKind },
    LaunchSession { path: PathBuf, title: String, message: Option<String> },
    StartSession { session_id: Ulid },
    StopSession { session_id: Ulid },
    RestartSession { session_id: Ulid },
    SendMessage { session_id: Ulid, message: String },
    RemoveSession { session_id: Ulid },

    // T2 — Modify Infra (Sebastian only, or with grant)
    CreateWorktree { session_id: Ulid, branch: String },
    FinishWorktree { session_id: Ulid, merge: bool },
    SetSessionParent { session_id: Ulid, parent_id: Ulid },
    RenameSession { session_id: Ulid, new_title: String },
    MoveSessionToGroup { session_id: Ulid, group: String },
    ConfigureConductor { name: String, config: ConductorConfig },

    // T3 — Privileged: Host Observation (Sebastian only, confirmed, logged)
    ReadHostFile { path: PathBuf },

    // T3 — Privileged: Host Mutation (Sebastian only, confirmed, logged)
    WriteHostFile { path: PathBuf, content: Vec<u8> },
    ModifyGitState { repo: PathBuf, operation: GitOperation },  // push, branch delete, etc.

    // T3 — Privileged: Host Execution (binary allowlist + named templates only)
    ExecuteHostCommand { template: CommandTemplate },  // e.g., CargoTest, NpmTest — NOT raw argv
    RestartService { service: ServiceName },

    // T3 — Privileged: External Network Write
    ExternalNetworkWrite { domain: String, method: HttpMethod, path: String },

    // T3+ — Break Glass (local-only, fully logged, bridge-unreachable, explicitly scary)
    BreakGlass { command: Vec<String>, cwd: PathBuf, justification: String },
}
```

**No `Shell(String)` variant.** `ExecuteHostCommand` uses a `CommandTemplate` enum with named, validated commands — not raw argv. `python3 -c "..."` or `node -e "..."` bypass argv restrictions, so raw commands are only available via `BreakGlass` which is local-only, fully logged, and requires explicit justification.

**Capabilities are the internal model; tiers are UX presets.** The policy engine evaluates capabilities (ReadHostFile, ModifyGitState, etc.). Tiers (T0-T3+) are approval UX groupings. Workflow bundles allow approving related capabilities as a unit (e.g., "test and deploy" = ExecuteHostCommand(CargoTest) + ModifyGitState(Push)).

## The Authority Boundary (CRITICAL)

**Terminal parsing NEVER grants authority.** This is the single most important architectural rule.

```
AUTHORITY PATH (structured, machine-verified):
  Agent calls MCP tool → host-side MCP server → ActionRequest → ops-policy → execute

OBSERVATION PATH (fuzzy, best-effort):
  Terminal output → ToolAdapter::parse_output() → AgentSignal (status/progress only)
```

The agent requests privileged operations through a **host-side MCP server** mounted into the container via Unix socket. The MCP server translates tool calls into `ActionRequest`s routed through `ops-policy`. The conductor builds the executable host action from the structured MCP request — never from parsed terminal output.

```rust
// MCP tool schema (exposed to agent inside container)
// This is the SOLE authority path for privileged operations
request_approval({
    action: "ReadHostFile",
    path: "/etc/hosts",
    reason: "Need to check local DNS entries for API endpoint"
})

request_approval({
    action: "ModifyGitState",
    operation: "push",
    repo: "/workspace/project",
    branch: "feature/new-api"
})
```

**MCP servers mounted into containers must be thin policy-mediated proxies.** They route through ops-policy, never access the host directly. This prevents the confused deputy problem — an agent can't call an MCP tool that reads `~/.ssh/id_rsa` because the MCP server doesn't have host access, it has policy access.

`ToolAdapter::parse_output()` remains for **observability only** — detecting session state (running/waiting/error), progress tracking, completion signals. It has confidence levels and a test corpus versioned against Claude Code releases. It never produces an `ActionRequest`.

---

## Trust Zones

```
Z0 — Untrusted Ingress    Slack/Telegram payloads, external content
Z1 — Control Plane        CLI + conductor orchestration logic
Z2 — Agent Runtime        tmux sessions (unsandboxed MVP) or Apple Containers (post-MVP)
Z3 — Privileged Host Ops  filesystem, network, process operations
```

### Zone Transition Table

| Transition | Allowed Subjects | Data Crossing | Approval Type | Origin Behavior | Audit |
|-----------|-----------------|---------------|---------------|----------------|-------|
| Z0 → Z1 | Bridge adapters | Sanitized text only (size-limited, encoding-checked, control chars stripped) | Auto (policy engine) | Origin preserved from platform identity | Every message logged |
| Z1 → Z2 | Conductor | Task assignments, approval responses | Auto for T0-T1, policy for T2+ | Origin carried through | Action + session logged |
| Z1 → Z3 | Policy engine | Structured Action only | T3: human-confirmed. T3+: human-approved with TTL grant | `HumanApproved` wraps original origin | Full argv/cwd/env logged |
| Z2 → Z1 | Agent (via runtime adapter) | Status updates, approval requests, completion signals | Auto (agent can request, conductor decides) | `AgentGenerated { session_id }` | Request + decision logged |
| Z2 → Z3 | BLOCKED in MVP | N/A | N/A | N/A | Attempt logged as violation |

### Permission Tiers → User Mapping

| User | Channel | Ceiling | Notes |
|------|---------|---------|-------|
| Sebastian | CLI | T0-T3+ | Full access, T3 with confirmation |
| Sebastian | Telegram | T0-T3 | No T3+ via bridge |
| Paul | Slack | T0-T1 | Read + operate only |
| Automated | Heartbeat | T0 + predefined T1 | Status checks + safe auto-responses |
| Agent | Container/tmux | Requests only | Agent requests, conductor evaluates |

---

## Conductor-Agent Protocol

The Action enum governs the **orchestration layer**. Agents (Claude Code, Codex) speak natural language in terminals. The runtime adapter translates between these worlds.

### Protocol (trait definitions in `ops-core`)

```rust
// Conductor → Agent (via runtime adapter, translated to tool-specific format)
pub enum ConductorMessage {
    TaskAssignment { instructions: String },
    ApprovalResponse { request_id: Ulid, approved: bool, constraints: Option<String> },
    StopRequest { reason: String },
    Ping,
}

// Agent → Conductor (parsed from tool-specific output by runtime adapter)
pub enum AgentSignal {
    StatusUpdate { state: SessionState },
    ApprovalRequest { description: String, action_hint: Option<Action> },
    CompletionSignal { summary: String },
    Heartbeat,
}

// Runtime translates between structured protocol and actual agent interface
pub trait SessionRuntime {
    async fn launch(&self, config: &SessionConfig, policy: &PolicyContext) -> Result<SessionHandle>;
    async fn send(&self, handle: &SessionHandle, msg: ConductorMessage, policy: &PolicyContext) -> Result<()>;
    async fn read_output(&self, handle: &SessionHandle) -> Result<String>;
    async fn status(&self, handle: &SessionHandle) -> Result<SessionState>;
    async fn attach(&self, handle: &SessionHandle) -> Result<()>;
    async fn stop(&self, handle: &SessionHandle, policy: &PolicyContext) -> Result<()>;
}

// Tool-specific behavior abstraction
pub trait ToolAdapter {
    fn status_patterns(&self) -> &[StatusPattern];  // regex for detecting running/waiting/error
    fn hook_format(&self) -> HookFormat;             // how this tool sends status events
    fn translate_send(&self, msg: ConductorMessage) -> String;  // structured → terminal input
    fn parse_output(&self, raw: &str) -> Vec<AgentSignal>;      // terminal output → structured
}
```

**MVP:** `ClaudeCodeAdapter` is the only `ToolAdapter` implementation. Codex adapter added later — the abstraction costs nothing upfront.

**Container future:** When Apple Containers are added, the conductor-agent channel becomes a Unix socket mounted into the container instead of tmux pane capture. The protocol stays the same; only the transport changes.

---

## Sandbox Architecture (Apple Containers)

Containers are **not optional** — they're the core security mechanism. Without them, an agent can read any file, write arbitrary scripts, and exfiltrate data. The policy engine can only restrict orchestration-layer actions; containers restrict what happens inside the agent session itself.

```
Conductor (Rust, on host)              Container (sandboxed agent)
├─ Policy engine                        ├─ Claude Code (or Codex, etc.)
├─ Approval gateway                     ├─ Project files (mounted rw)
├─ Audit log                            ├─ MCP sockets (mounted via --publish-socket)
│                                       ├─ ~/.claude config (mounted ro)
│                                       └─ No ~/.ssh, no host shell, no other sessions
│
├─ Agent requests privileged op ◄──────── Unix socket (structured protocol)
├─ Evaluate tier + grants
├─ Approve/deny
└─ Execute on host if approved
```

**Network policy (two execution classes):**
- *Offline repo worker:* No outbound network. Filesystem scoped to project directory only.
- *Limited-network worker:* Allowlisted endpoints only (api.anthropic.com, github.com, registry.npmjs.org). No local LAN access.

`SessionRuntime` exposes execution class via `fn capabilities(&self) -> ExecutionCapabilities`.

### Execution Classes

```
┌────────────────┬──────────────┬──────────────────┬───────────────────┐
│                │  offline     │  research        │  builder          │
│                │  worker      │  worker           │                   │
├────────────────┼──────────────┼──────────────────┼───────────────────┤
│ Network        │ None         │ GET allowlisted  │ Full allowlisted  │
│ Filesystem     │ Project (rw) │ Project (rw)     │ Project (rw)      │
│ Local LAN      │ Blocked      │ Blocked          │ Blocked           │
│ Tier ceiling   │ T0           │ T1               │ T1                │
│ API keys       │ None         │ Read-only APIs   │ All project APIs  │
│ Git            │ Local only   │ Pull only        │ Push allowed      │
│ Use case       │ Refactoring, │ Web research,    │ Paul's workflow,  │
│                │ code review  │ summarization    │ image/video gen   │
└────────────────┴──────────────┴──────────────────┴───────────────────┘
```

Sessions get assigned an execution class. The class determines container mount config, network policy, env vars, and tier ceiling. This replaces profiles as the primary security abstraction.

### Unsandboxed Mode (Conductor only)

**Default: all agent sessions are sandboxed**, including Sebastian's. Only the conductor itself runs unsandboxed on the host (it needs host access for session management, approval gateway, and bridge).

To launch an unsandboxed agent session, Sebastian must explicitly pass `--unsandboxed` at creation time. This flag is:
- Immutable after creation (can't be changed later)
- Local-only (bridge-originated sessions can never be unsandboxed)
- Visibly distinct in status, logs, and audit trail (separate audit category)
- Documented as the **primary remaining attack surface**

Features built for unsandboxed mode must not quietly become required by sandboxed sessions.

---

## Approval Gateway (from NanoWilliams)

```rust
pub struct ApprovalGrant {
    pub id: Ulid,
    pub principal_id: String,       // who
    pub action: Action,             // what (or action pattern)
    pub resource_scope: String,     // where (path, session, etc.)
    pub constraints_json: Option<String>,
    pub expires_at: OffsetDateTime, // TTL (default 30 days)
    pub max_uses: Option<u32>,
    pub issued_by: String,          // who approved
    pub issued_at: OffsetDateTime,
}
```

- All T3 and selected T2 actions require an approval grant
- Enforced at execution time, not just request time
- Auto-deny on timeout (5 min default)
- Expired grants silently ignored (fail closed)
- Stored in SQLite `approval_grants` table

---

## Audit Trail (HMAC-chained JSONL)

Each event includes content hash, previous event hash (chain), and HMAC over both. Tampering breaks the chain.

```json
{
  "id": "01JQXYZ...",
  "ts": "2026-04-05T15:00:00Z",
  "action": "SendMessage",
  "origin": {"BridgeSlack": {"user_id": "U123", "channel_id": "C456"}},
  "session": "bookmark-extractor",
  "tier": "T1",
  "decision": "allowed",
  "prev_hash": "abc123...",
  "hmac": "def456..."
}
```

~20-30 lines in `ops-audit`. SQLite index references JSONL offsets + hashes for fast verification.

---

## Input Normalization (Detail)

**Important framing:** This is **normalization for parser safety and suspicion scoring**, NOT a trust upgrade. Normalized content is not trustworthy — it's just safe to parse. The container boundary is the trust boundary, not the sanitizer.

Normalization happens at **two points**: bridge ingress and session output read.

### Bridge Ingress (all inbound messages)

```
Raw message from Slack/Telegram
  │
  ├─ 1. Size limit (reject > 32KB)
  ├─ 2. Encoding normalization (UTF-8 only)
  ├─ 3. strip-invisible logic:
  │     ├─ Zero-width characters (U+200B, U+200C, U+200D, U+FEFF, etc.)
  │     ├─ Invisible Unicode (tag chars U+E0001-U+E007F)
  │     ├─ Directional overrides (U+202A-U+202E, U+2066-U+2069)
  │     ├─ Homoglyph detection (Cyrillic а vs Latin a, etc.)
  │     ├─ Control characters (except \n, \t)
  │     ├─ Variation selectors (U+FE00-U+FE0F)
  │     └─ Steganographic whitespace patterns (tab/space encoding)
  ├─ 4. If anything stripped: log event to audit trail with details
  ├─ 5. Add header: [SANITIZED: N chars removed from {categories}]
  └─ 6. Forward clean text with ActionOrigin
```

**Coverage:** 11/13 st3gg text stego methods (from existing `strip-invisible` tool at `~/.local/bin/strip-invisible`). Port logic into `ops-policy` as a Rust function.

**Multilingual handling:** Homoglyph detection uses a character-class approach — flag mixed-script text (Latin + Cyrillic in same word) rather than blocking entire scripts. Paul's clients may send Portuguese text — that's fine (Latin script throughout). Flag but don't block; log the detection.

### Session Output Sanitization

When the conductor reads agent output (via `SessionRuntime::read_output()`), that output may contain injected content from web pages the agent visited (indirect prompt injection).

```
Agent output from tmux pane
  │
  ├─ 1. Strip invisible characters (same logic as ingress)
  ├─ 2. Detect potential injection markers:
  │     ├─ "SYSTEM:", "ADMIN:", "IMPORTANT:" prefixes
  │     ├─ Markdown/HTML that looks like system instructions
  │     ├─ Base64 encoded blocks above threshold size
  │     └─ Suspicious URL patterns (data:, javascript:)
  ├─ 3. Flag but don't strip (conductor needs to see the output)
  └─ 4. Log any detections to audit trail
```

### Network Read/Write Split (from PLAN-SECURITY.md Layer 6)

Inside containers, distinguish network operations by risk:

| Type | Methods | Permission | Default for Paul |
|------|---------|------------|-----------------|
| `http.read` | GET only | Low bar, bounded response size, strict timeout | Allowed (allowlisted domains) |
| `http.write` | POST/PUT/PATCH/DELETE | Requires explicit domain+endpoint allowlist | Allowed for known APIs only |

A compromised agent could exfiltrate data via POST to an attacker's domain. The network allowlist blocks unknown domains, and `http.write` restrictions add defense-in-depth within the allowlist.

## Bridge Identity Resolution

1. Platform identity (Slack user ID, Telegram sender ID)
2. Authenticated mapping to system actor via config table
3. Channel-scoped capability ceiling (DM vs. public channel)
4. Per-action approval context with anti-replay (timestamp window)
5. Conversation-state controls (previous approval doesn't carry forward)

---

## State Management

- **Source of truth:** SQLite (WAL mode)
- **Audit/forensics:** Append-only JSONL with HMAC chain
- **No hand-edited JSON** — state.json becomes a derived view
- **Migrations:** `sqlx::migrate!()` compiled into binary, forward-only

### SQLite Tables

```
sessions, session_groups, session_links
conductors, conductor_children, heartbeats
messages, bridge_inbox, bridge_outbox
approval_requests, approval_grants
audit_index
```

### Tmux Integration

- Each session = one tmux window (keep tmux, don't replace)
- `tokio::process::Command` wrapper (not tmux_interface crate)
- Pane capture for output (not control mode in MVP; evaluate `-C` in Phase 2)
- `SessionRuntime` trait is tmux-agnostic — no tmux types leak into core/policy/conductor
- Startup check: verify tmux installed (3.3+ recommended)

---

## Simple Skill/Tool System

Not agent-deck's full skill management. A minimal per-session config:

```toml
[tools.claude]
command = "claude"
adapter = "claude-code"
skills = ["~/.claude/skills/social-research", "~/.claude/skills/audit-skill"]

[tools.codex]
command = "codex"
adapter = "codex"
```

`ToolAdapter` trait handles tool-specific behavior. Skills are just directories attached via tool config — no discovery, no source management, no marketplace.

---

## Feature Tiers (Updated)

### MVP — 48 features

**Session core:** 1, 2, 3, 4, 9, 10
**Status:** 12, 13, 14, 17
**Hierarchy:** 18, 19, 20
**Conductor:** 28, 29, 30, 31, 32, 33, 34, 35
**Bridges:** 36, 37, 39
**Tmux:** 40, 41, 42
**Worktrees:** 45, 46
**Hooks:** 90, 93
**Ops:** 95, 98
**CLI:** 101, 104
**Security (current):** 107 (Keychain), 109, 110
**Security (new):** 111, 112, 113, 114, 115, 116, 117, 118, 119
**Simple skills:** minimal tool config system

### Phase 2 — 25 features

5, 6, 7, 8, 11, 15, 16, 21, 22, 25, 26, 38, 43, 44, 47, 48, 49, 94, 96, 97, 102, 103, 105, 106
Plus: Dashboard mode (ratatui status board, inspired by cmux — see `drafts/design-ref/cmux-inspiration.png`)

### Phase 3 — Polish

Dashboard mode (ratatui status board, inspired by cmux). Global search. Try command.

### Drop — 37 features

50-52 (MCP management), 56-58 (Skills management UI), 59-60 (Docker), 61-66 (SSH/Remote), 67-71 (Costs as billing — but keep per-session budget guard as security), 72-81 (full TUI), 82-86 (Web), 87-89 (OpenClaw), 91, 92, 99, 100, 120 (WASM)

---

## Build Order (Critical Path)

```
Pre-Build ──→ Step 1 ──→ Step 2 ──→ Step 3 ──→ Step 4 ──→ Step 5
(checklist)   ops-core   ops-policy  ops-store   ops-runtime  ops-cli
                                                 (tmux+container)
                                                      │
                                    Step 6 ──→ Step 7 ──→ Step 8
                                    ops-conductor  bridge     bridge
                                                   (types)    (live)
                                                        │
                                              Step 9 ──→ Step 10 ──→ Step 11 ──→ Step 12
                                              worktrees  hardening    shadow       cutover
```

| Step | Crate(s) | What | Milestone |
|------|----------|------|-----------|
| 0 | — | **Pre-build checklist** (see above): Container PoC, MCP-IPC schema, IPC protocol spec, Action split, HMAC key lifecycle, Principal model | Architecture validated |
| 1 | ops-core | Action enum (effect-class split), ActionOrigin, Principal, all traits (SessionRuntime, ToolAdapter, MessageSink, ActionRouter, PolicyContext), MCP tool schema, domain models | Type system defined |
| 2 | ops-policy + ops-audit | Capability evaluation, trust zone checks, grant system, input normalization (strip-invisible ported to Rust), HMAC-chained JSONL with Keychain-backed key, policy versioning, table-driven auth tests | Security compiles into everything from here |
| 3 | ops-store | SQLite schema, migrations, session/group CRUD, approval grants table | Can persist sessions |
| 4 | ops-runtime | Tmux backend + container backend (feature-gated), ClaudeCodeAdapter, hook parsing, status detection, host-side MCP server (policy-mediated proxy), IPC protocol implementation, execution classes | Can manage live sessions (sandboxed + unsandboxed) |
| 5 | ops-cli | Clap commands for session lifecycle | CLI parity with core agent-deck commands |
| 6 | ops-conductor | Heartbeat loop with state reconciliation, child notifications, auto-response/escalation, budget guard, approval gateway notifications, per-session MCP socket isolation | Conductor pattern works |
| 7 | ops-bridge (types) | Bridge adapter types, message parsing, Principal resolution, normalization, ActionOrigin mapping | Attack surface testable without live connections |
| 8 | ops-bridge (live) | Telegram long-polling, then Slack Socket Mode (budget 2x for Slack) | Bridge replaces bridge.py |
| 9 | — | Worktrees, simple skill/tool config | Feature parity with what we use |
| 10 | — | Hardening: rate limits, approval fatigue mitigations (cool-down, anomaly detection), WebFetch output normalization, image re-encode pipeline, network read/write split, crash recovery, MCP server audit, ANSI escape stripping, git hook restrictions | Production-ready |
| 11 | — | Shadow mode: compare normalized ActionRequests between Rust and Go systems for 2 weeks | Validate correctness |
| 12 | — | Cutover | Kill agent-deck + bridge.py |

---

## Migration Strategy

**Incremental, not big bang.**

1. Steps 1-5: build and test CLI independently
2. Shadow mode (Step 11): Rust mirrors Go decisions, logs diffs
3. Cut over one use case at a time (new sessions first, then existing)
4. Keep agent-deck installed as fallback until confident
5. Keep bridge.py as transitional Slack adapter if native Rust Slack takes longer

---

## Dependency Budget (~25 crates)

### Core
- `tokio` + `tokio-util` — async runtime + CancellationToken
- `clap` — CLI parsing
- `serde` + `serde_json` — serialization
- `toml` — config parsing
- `thiserror` + `anyhow` — error handling
- `tracing` + `tracing-subscriber` — structured logging
- `time` — timestamps
- `ulid` — unique IDs
- `regex` — pattern matching (status detection, sanitization)

### Storage
- `sqlx` (sqlite, migrate) — database

### Bridge/Network
- `reqwest` (rustls-tls, json) — HTTP client (Telegram API)
- `tokio-tungstenite` — WebSocket (Slack Socket Mode)

### Security
- `hmac` + `sha2` — audit chain integrity
- `secrecy` — compile-time secret logging prevention
- `zeroize` — memory safety for sensitive values
- `security-framework` — macOS Keychain access (HMAC key, secrets)

### Deferred
- `governor` — rate limiting (add when we know what we're rate-limiting)
- `portable-pty` — direct PTY (if we want non-tmux backend)
- `ratatui` — dashboard mode (Phase 2)

**Explicitly excluded:** no `git2`, no web frameworks, no ORMs beyond sqlx, no plugin runtimes, no `async-trait` (native since Rust 1.75), no `typed-builder`, no `shlex`, no `camino`.

---

## Testing Strategy

- **Property-based:** Action enum × capability mapping exhaustiveness, ActionOrigin × Principal × policy decision coverage
- **Table-driven auth tests:** `(origin, action, expected_decision)` triples as the first tests in ops-policy. Deny-by-default invariant tests.
- **Integration:** Real tmux server in CI, session lifecycle assertions
- **Security corpus:** Bridge input normalization against known Slack/Telegram injection patterns, ST3GG red-team testing (all 112 stego techniques)
- **Shadow mode:** Compare normalized `ActionRequest`s between Rust and Go systems (structured intent, not terminal bytes). Build regression corpus from real events.
- **Policy versioning:** `policy_version` field on configs and audit entries from Step 2
- **Container breakout tests:** When Apple Containers are added (Phase 3)

---

## Error Recovery & State Reconciliation

- **Startup:** Reconcile SQLite state against actual tmux/container sessions (discover orphans, mark missing as error, emit `Action::ReconcileSession` to audit)
- **Heartbeat:** Compare SQLite session state against actual runtime state every cycle. Detect zombie processes, dead containers, state mismatches.
- **Running:** Detect and restart crashed bridge connections with backoff
- **Running:** Clean up expired approval grants (TTL enforcement)
- **Running:** Recover in-flight approval requests from dead sessions (mark expired, notify)
- **Running:** Rotate audit logs
- **Crash:** Agent sessions continue in tmux/containers. Conductor recovers by re-attaching and replaying from tmux history / IPC replay cache.
- **Per-session MCP isolation:** Each session gets its own MCP socket directory. No MCP server sharing between sessions (prevents cross-session context leaks).

---

## Items from PLAN-SECURITY.md Now Incorporated

Cross-reference with the original 8-layer security plan:

| Layer | Status in agent-ops |
|-------|-------------------|
| 1. Input sanitization | ✅ ops-policy (strip-invisible ported to Rust, bridge ingress + output read) |
| 2. Permission tiers | ✅ Action enum + ActionOrigin + tier ceiling per user |
| 3. Sandboxed execution | ✅ ops-container (Apple Containers, execution classes) |
| 4. Audit trail | ✅ ops-audit (HMAC-chained JSONL) |
| 5. Approval gates + TTL | ✅ ops-policy (approval gateway from NanoWilliams) |
| 6. Network read/write split | ✅ Container network policy + http.read/http.write distinction |
| 7. Rate limiting + sender allowlist | ✅ ops-bridge (hardcoded sender IDs, rate limits) |
| 8. Supply chain hardening | ✅ Rust-only deps, no npm/pip, pinned Cargo.lock, MCP audit in hardening pass |

**Additional items from PLAN-SECURITY.md now covered:**
- Sanitization on session output read (indirect prompt injection)
- Multilingual content handling (mixed-script detection, not script blocking)
- MCP server verification (hardening pass, Step 10)
- Credential injection from Keychain into container env (ops-container)
- Action Risk Matrix maps directly to the Action enum tier assignments

**All 8 layers accounted for.** Nothing left behind.

## What to Use from Existing Projects

| Project | Use as | What to take |
|---------|--------|-------------|
| **NanoWilliams** | Pattern source | Approval gateway, path validation, tiered permissions, audit schema |
| **IronClaw** | Pattern reference | Bridge routing, trust boundaries, WASM plugin model (for future) |
| **Agent of Empires** | Pattern reference | Tmux/worktree UX patterns |
| **cmux** | Design reference | UI layout and information architecture (see `drafts/design-ref/`) |

**Fork nothing. Depend on nothing from these projects.**

---

## Known Limitations & Accepted Risks

1. **npm supply chain inside Paul's container:** Builder execution class allows `registry.npmjs.org`. A malicious npm package can access Paul's project files and API tokens. Container protects the host, not the project. Mitigation: `package-lock.json` integrity verification, documented with explicit user acknowledgment.
2. **Git hook injection:** Paul's builder can `git push` to GitHub. A malicious commit could trigger GitHub Actions that exfiltrate repo secrets. Mitigation: branch protection rules, PR-based workflow, repo-level restrictions in conductor policy.
3. **Adversarial perturbations optimized for JPEG robustness:** Research-grade image attacks that survive re-encode. Unlikely in the wild against our setup.
4. **Semantic manipulation / biased framing:** Model reasoning vulnerability, outside our control. Mitigated by midflight cross-checks for high-stakes decisions.
5. **Approval fatigue:** Human cognitive vulnerability. Mitigated by rate limits, cool-downs, anomaly detection — but fundamentally requires human vigilance.
6. **Sebastian unsandboxed sessions:** When explicitly launched with `--unsandboxed`, these have full host access. Prompt injection via fetched content is unmitigated. This is the primary remaining attack surface.
7. **ANSI escape injection in tmux output:** Terminal escape sequences can corrupt ToolAdapter parsing. Mitigated by stripping ANSI escapes before parsing (hardening pass).
8. **TOCTOU on approval grants:** Mitigated by two-phase validation (check at request time, verify at execution time).

## Resolved Design Decisions

- **ops-audit stays separate from ops-policy.** Audit interface is tiny and stable (`fn append(event: &AuditEvent) -> Result<()>`). Policy churns. Merging couples stable with unstable.
- **Shadow mode validates normalized ActionRequests**, not terminal output bytes. Equivalent intent = parity.
- **ops-container merged into ops-runtime** as feature-gated backend. `TmuxRuntime` and `ContainerRuntime` implement the same `SessionRuntime` trait.

---

*Reviewed by: Vigil, Codex (GPT-5.3), Ting forum (Claude + Codex + Gemini, 2 rounds x 2)*
*Security analysis: DeepMind Agent Traps paper, Pliny ST3GG toolkit (112 techniques)*
*Design inspiration: cmux (Swift/libghostty), NanoWilliams (Rust security patterns)*
