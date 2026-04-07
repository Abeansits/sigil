# Security Plan — Multi-Conductor Agent System

**Created:** 2026-04-02
**Status:** Draft
**Context:** Supply chain attacks (axios), advanced prompt injection tools (Pliny's st3gg — 112 stego techniques, 13 text methods), and the reality that Paul has implicit root-equivalent access to Sebastian's machine through Slack.

---

## Threat Model

### Attack Surface

```
Paul's Slack ──→ Vs conductor ──→ full shell on Sebastian's Mac
External content ──→ WebFetch/gws ──→ agent context ──→ shell commands
npm/MCP supply chain ──→ code execution in agent context
Crafted message ──→ any conductor ──→ session-to-session escalation
Telegram/Slack ──→ bridge.py ──→ network-facing Python process
```

### Threat Actors

| Actor | Capability | Motivation | Likelihood |
|-------|-----------|------------|------------|
| Compromised Slack account | Full Vs access via Paul's credentials | Lateral movement, data theft | Medium |
| Prompt injection via content | Embedded instructions in web pages, emails, files | Agent hijacking | High |
| Supply chain (npm/pip/MCP) | Code execution during install or runtime | Cryptomining, data exfil, backdoor | Medium-High (axios just happened) |
| Pliny-style attacker | Steganographic payloads, invisible Unicode, homoglyphs | Jailbreak, demonstrate vulnerabilities | Low (targeted) but educational |

### Trust Zones (Current — Broken)

```
EVERYTHING IS TRUSTED
Paul = Sebastian = External Content = MCP Servers = npm packages
All have: shell access, file read/write, session control, credential access
```

### Trust Zones (Target)

```
ZONE 1 — TRUSTED (local, Sebastian only)
  Sebastian's Telegram → ops conductor → full shell
  Direct CLI → any session → full access

ZONE 2 — SEMI-TRUSTED (local, gated)
  Automated processes → conductor → approval gate for destructive ops

ZONE 3 — UNTRUSTED (sandboxed)
  Paul's Slack → cloud conductor → no local access
  External content → sandboxed processing → sanitized output only
```

---

## Current Defenses

| Defense | Status |
|---------|--------|
| `strip-invisible` CLI tool | Done — catches 11/13 st3gg text stego methods |
| Input sanitization on bridge | None |
| Permission model | None — all users are root |
| Audit trail | task-log.md (actions only, no security context) |
| Sandboxing | None — all agents have full shell |
| MCP/plugin verification | None — trusted implicitly |
| Rate limiting | None |
| Anomaly detection | None |

---

## Proposed Layers

### Layer 1: Input Sanitization (do first)

**What:** Strip/flag dangerous content before it reaches any conductor's context.

**Where to implement:** In `bridge.py`, before forwarding messages to conductors.

**Components:**
- Integrate `strip-invisible` logic into bridge message processing
- Flag messages with hidden characters — log the finding, strip the payload, forward the clean text
- Add a warning header: `[SANITIZED: 371 hidden chars removed]` so the conductor knows something was cleaned
- Apply to all inbound channels: Telegram, Slack, outbox files

**For session output too:** When conductors read session output via `agent-deck session output`, the output could contain injection from external content the session processed. Consider sanitization on read as well.

**Effort:** Small. **Impact:** High — blocks the most common injection vector.

### Layer 2: Permission Tiers

**What:** Different users get different command capabilities.

**Design:**

| Tier | Who | Can Do | Cannot Do |
|------|-----|--------|-----------|
| Owner | Sebastian (Telegram) | Everything | — |
| Partner | Paul (Slack) | Query sessions, read status, send business messages, trigger predefined workflows | Shell commands, file writes, session creation/deletion, system config |
| Automated | Heartbeat, cron | Status checks, predefined actions | Anything destructive, anything new |
| External | Web content, APIs | Nothing directly | Everything — processed in sandbox |

**Implementation options:**

A. **Bridge-level enforcement:** Bridge tags messages with source tier. Conductor checks tier before executing. Simple but relies on conductor discipline (prompt-based, not enforced).

B. **Conductor CLAUDE.md rules:** Add explicit rules: "Messages from Slack are PARTNER tier. Never execute shell commands, file writes, or session management from PARTNER messages." Lighter weight, but breakable via injection.

C. **Bridge-level command allowlist:** Bridge only forwards messages matching an allowlist pattern for non-owner tiers. Everything else gets a "not authorized" response. Enforced at the code level, not the prompt level.

**Recommendation:** C for hard enforcement + B as defense-in-depth. Don't rely on the LLM to enforce security boundaries — enforce them in code.

**Effort:** Medium. **Impact:** Critical — this is the biggest gap.

### Layer 3: Sandboxed Execution for Untrusted Inputs

**Two options — local containers or cloud. Evaluate both.**

#### Option A: Apple Containers (local sandbox)

NanoWilliams was designed around this. Run Vs inside an Apple Container with explicit mounts:

```
Apple Container (Vs / Paul's agent)
├── /workspace/project  ← Paul's project folders (read-write, mounted)
├── /workspace/scratch  ← session scratchpad (persistent)
├── /home/agent/.codex  ← agent auth/config
└── NO access to: ~/.ssh, ~/.aws, credentials, other sessions, host shell
```

**What this gives us:**
- Paul's agent can read/write project files — full capability for business work
- Cannot access credentials, SSH keys, or other sessions
- Cannot execute commands on the host
- Sebastian's security.rs blocklist enforced by container boundary, not prompt rules

**Network gap:** Apple Containers had limited/no network controls when NW was built. Two mitigations:
- Rely on Codex's `--sandbox workspace-write` for network policy
- Or use Claude Code's sandboxing rules for network restrictions
- Revisit if Apple has shipped network controls since

**Tradeoffs vs cloud:**
- (+) No latency — runs locally
- (+) No cloud compute cost
- (+) Full MCP server access via mounted sockets
- (+) Offline capable
- (-) Still on Sebastian's machine (power/sleep affects it)
- (-) Container escape is theoretically possible (but hard)
- (-) Need to build/maintain container orchestration

#### Option B: Cloud Execution (remote sandbox)

**What:** Move untrusted workloads to sandboxed cloud environments instead of running them locally.

**Why:** Instead of building local sandboxing (hard, easy to get wrong), piggyback on existing cloud infrastructure from Anthropic (Claude Code remote agents) and OpenAI (Codex remote execution) that already provides:
- Sandboxed containers with no local filesystem access
- Built-in audit logging
- Git-based state sync
- Process isolation

**Architecture:**

```
UNTRUSTED (cloud, sandboxed)              TRUSTED (local)
─────────────────────────                 ──────────────────
Paul's Slack ──→ Cloud Vs conductor       Sebastian ──→ Local ops conductor
                 (sandboxed, no shell,                  (full access)
                  no local fs)
                      │
                      ▼
                 Git repo / outbox  ←── approval gate ──→ Local pickup
```

**What Paul's cloud agent CAN do:**
- Research, draft documents, analyze data
- Read/write to shared git repos
- Query business context from shared memory
- Create tasks/requests for local execution

**What it CANNOT do:**
- Access Sebastian's filesystem
- Execute shell commands locally
- Read credentials or tokens
- Send messages to other local sessions

**Existing infrastructure:**
- Claude Code: `RemoteTrigger`, `/schedule` skill for remote agents
- Codex: `--remote` flag for cloud execution
- Git repos as the natural sync point

**Tradeoffs:**
- (+) Security boundary that would take months to build locally
- (+) Audit logging for free
- (+) No prompt injection can reach local shell
- (-) Added latency (seconds, not critical for Paul's use case)
- (-) Cloud agent needs project context without local files (solvable via git)
- (-) Some tasks genuinely need local access (request via outbox + approval)
- (-) Cost (cloud compute on top of local — evaluate)

**Evaluate:** Prototype with one workflow (e.g., Paul asking about project status). Measure latency, capability gaps, and cost. If viable, migrate Vs entirely to cloud.

**Effort:** Medium-Large. **Impact:** High — eliminates the biggest risk (Paul = root).

### Layer 4: Audit Trail

**What:** Security-aware logging of all external interactions.

**What to log:**
- Every message from external sources (Slack, Telegram) with source, tier, timestamp
- Every sanitization event (what was stripped, from where)
- Every command executed as a result of external input
- Every permission denial
- Every session-to-session message

**Format:** Append-only file, separate from task-log.md:

```json
{"ts": "2026-04-02T15:00:00Z", "source": "slack", "user": "paul", "tier": "partner", "action": "message", "sanitized": 0, "content_hash": "abc123"}
{"ts": "2026-04-02T15:00:01Z", "source": "slack", "user": "paul", "tier": "partner", "action": "denied", "reason": "shell_command_not_allowed"}
```

**Where:** `~/.agent-deck/conductor/audit.jsonl`

**Effort:** Small. **Impact:** Medium — doesn't prevent attacks but enables detection and forensics.

### Layer 5: Approval Gates with Scoped Grants + TTL

**What:** High-risk operations require approval, but approvals mint *temporary, scoped grants* so you don't re-approve the same thing forever.

**Design (from NanoWilliams `action_gateway.rs`):**

```
Action request arrives
  → Matching valid grant exists? → Execute
  → No grant? → Create approval request → Notify Sebastian via Telegram
    → Approved before timeout? → Mint scoped grant (TTL 30 days) → Execute
    → Denied? → Audit log, done
    → Timeout (5 min)? → Auto-deny + audit log + notify
```

**Scoped grants:**
- Capability-specific: "Paul can trigger deploy workflow"
- Time-limited: 30-day TTL by default, configurable
- Constraint-bound: allowed domains/methods for HTTP, specific shortcuts, etc.
- Expired grants are silently ignored — fail closed

**Auto-deny on timeout:**
- If Sebastian doesn't respond within 5 minutes, request is denied
- Logged to audit trail
- Notification sent: "Auto-denied: [action] (timeout)"
- Prevents unattended approval requests from hanging forever
- Critical for overnight/unattended operation

**Grant storage:** SQLite table or simple JSON file:
```json
{
  "grants": [
    {
      "id": "g-001",
      "user": "paul",
      "capability": "deploy:staging",
      "constraints": {"project": "judah"},
      "expires": "2026-05-02T00:00:00Z",
      "granted_by": "sebastian",
      "granted_at": "2026-04-02T23:00:00Z"
    }
  ]
}
```

**Why this solves the security/capability tension:** Paul doesn't get permanent blanket access and doesn't need to ask permission for every small thing. He gets time-boxed, scoped access that auto-expires. Sebastian approves once, it works for 30 days, then needs renewal.

**Effort:** Medium. **Impact:** High — this is the bridge between security and usability.

### Layer 6: Network Policy (Read/Write Split)

**What:** Distinguish between low-risk reads (GET) and high-risk writes (POST/PUT/DELETE).

**Design (from NanoWilliams):**
- `http.read`: GET only, bounded response size, strict timeout. Lower permission bar.
- `http.write`: POST/PUT/PATCH/DELETE, requires explicit allowlist of domains/endpoints.

**Why:** Fetching a URL to summarize it is very different from POSTing data to an API. Our current setup treats them the same. A compromised agent could exfiltrate data via POST to an attacker-controlled domain.

**Implementation:** Bridge-level or conductor-rule enforcement. Partner tier gets `http.read` by default, `http.write` only via scoped grant.

**Effort:** Small. **Impact:** Medium.

### Layer 7: Rate Limiting + Sender Allowlist

**What:** Prevent flooding from compromised accounts and restrict who can talk to conductors.

**Design (from NanoWilliams):**
- **Sender allowlist:** Only approved user IDs can send messages through the bridge. Hardcoded in bridge config, not in conductor prompts.
- **Rate limiting:** Max messages per sender per minute/hour. Prevents a compromised Slack account from spamming commands faster than Sebastian can notice.

**Current state:** Bridge accepts messages from anyone in the configured Slack channels. No rate limits.

**Effort:** Small. **Impact:** Medium — basic hygiene that blocks the easiest attacks.

### Layer 8: Supply Chain Hardening

**What:** Reduce risk from compromised dependencies.

**Actions:**
- Pin all npm/pip dependencies to exact versions (no `^` or `~`)
- Use lockfiles and verify checksums
- Audit MCP server sources before enabling
- Review plugin code before installation (or at least scan for network calls, eval, exec)
- Consider running MCP servers in their own sandboxed processes
- Secrets in macOS Keychain (already done for Telegram token — systematize for all secrets)

**Effort:** Small (ongoing discipline). **Impact:** Medium — reduces a real and growing attack vector.

---

## Implementation Priority

| # | Layer | Effort | Impact | Why This Order |
|---|-------|--------|--------|----------------|
| 1 | Input sanitization | Small | High | Quick win, blocks most common vector |
| 2 | Permission tiers (bridge-level) | Medium | Critical | Paul = root is the biggest gap |
| 3 | Sender allowlist + rate limiting | Small | Medium | Basic hygiene, blocks easiest attacks |
| 4 | Audit trail | Small | Medium | Foundation for detection |
| 5 | Apple Container sandbox (prototype) | Medium-Large | Critical | The real fix — isolate Paul's agent |
| 6 | Approval gates + scoped grants/TTL | Medium | High | Security/capability balance |
| 7 | Network read/write split | Small | Medium | Prevents data exfiltration |
| 8 | Supply chain hardening | Small | Medium | Ongoing discipline |

### Phase 1 (next session)
- Integrate `strip-invisible` into bridge.py
- Add bridge-level command allowlist for Slack (Paul) messages
- Sender allowlist (hardcoded user IDs in bridge config)
- Create audit.jsonl logging

### Phase 2 (the big one)
- Prototype Apple Container for Vs/Paul's agent
  - Mount Paul's project folders read-write
  - Mount scratchpad for session persistence
  - Block access to ~/.ssh, ~/.aws, credentials, other sessions
  - Investigate Apple Container network controls (may have shipped since Feb)
  - Fall back to Codex/Claude sandboxing for network policy if needed
- Implement approval gates with TTL grants + auto-deny timeout
- Rate limiting per sender

### Phase 3 (evaluate + harden)
- If Apple Containers don't cover network: evaluate cloud execution as alternative
- Network read/write split
- Supply chain audit + pin dependencies
- Systematize Keychain usage for all secrets

---

## Design Principle: Security ≠ Capability Loss

The mistake is treating security as a single slider between "locked down" and "useful." It's not — it's a per-action decision based on who's asking and what they're doing.

### Action Risk Matrix

| Action | Risk | Owner (Sebastian) | Partner (Paul) | Automated |
|--------|------|-------------------|----------------|-----------|
| Read project files | Low | Allow | Allow | Allow |
| Write to project dir | Low-Med | Allow, log | Allow, log | Allow, log |
| Read .ssh/.aws/credentials | Critical | Block | Block | Block |
| Shell commands | Varies | Allow, log | **Block** | Predefined only |
| Fetch a URL | Medium | Allow (sanitize) | Allow (sanitize) | Allow (sanitize) |
| Install npm/pip package | High | Confirm | **Block** | **Block** |
| Send external message | Medium | Allow, log | Log + confirm | **Block** |
| Delete files | High | Confirm | **Block** | **Block** |
| git push / force push | High | Confirm | **Block** | **Block** |
| Create/delete sessions | Medium | Allow | **Block** | **Block** |
| Read session output | Low | Allow | Allow (own group) | Allow (own group) |
| Query status | None | Allow | Allow | Allow |

### What Paul Actually Loses
Almost nothing he uses today:
- Can still ask questions, get summaries, read status
- Can still trigger predefined workflows
- Can still draft documents, analyze data, research
- Can still read session output for his projects

What he loses: shell access, file deletion, package installation, session management — things he never needed and shouldn't have.

### What Sebastian Loses
Nothing except confirmation prompts on destructive operations — which is good practice regardless of security.

### NanoWilliams Precedent
Sebastian's own NanoWilliams project (`security.rs`) already implemented this pattern:
- Main user: full access
- Sub-groups: restricted to their own roots + explicit allowlist
- Blocked paths: hardcoded for .ssh/.aws/credentials (everyone, including main)
- Per-group write restrictions: non-main can't write outside their workspace

The key insight from NW: **the per-group allowlist didn't make the system less useful — it made it predictable.** Each group knew exactly what it could access, and the system enforced it at the code level, not the prompt level.

---

## Open Questions

1. **Can Claude Code remote agents access MCP servers?** If not, the cloud Vs would lose some capabilities (Gmail, etc.). May need a hybrid where cloud handles conversation and local handles tool calls.

2. **What's Paul's actual command surface?** Before building permission tiers, audit what Paul actually asks Vs to do. Might be simpler than we think — he may only need 5-6 command patterns.

3. **Bridge vs conductor enforcement:** Should the bridge refuse to forward unauthorized messages entirely, or forward them with a tier tag and let the conductor decide? Bridge enforcement is harder to bypass but less flexible.

4. **How do we handle legitimate multilingual content?** `strip-invisible` in paranoid mode catches Cyrillic homoglyphs, but Paul or clients might send actual multilingual text. Need a way to distinguish.

5. **Cost model for cloud execution:** What does running Vs in Claude Code cloud cost vs local? Need to factor in API costs, compute costs, and the value of not getting pwned.

---

*References:*
- *Pliny's st3gg: 112 stego techniques, 13 text methods, pip installable*
- *axios supply chain attack: April 2026*
- *Claude Code cache bugs: 6 bugs found via source leak, 2.5x cost multiplier*
- *strip-invisible: ~/.local/bin/strip-invisible (11/13 st3gg coverage)*
