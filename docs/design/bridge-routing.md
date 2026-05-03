# Bridge → Conductor Routing Design

**Status:** PROPOSAL — awaiting Sebastian's review
**Date:** 2026-05-02
**Author:** sigil-bridge-routing-design session

## Problem

Today both bridges build a `BridgeMessage` with `target_session: None` for every non-slash-command DM (`crates/sigil-bridge/src/slack.rs:80`, `crates/sigil-bridge/src/telegram.rs:85`). Those messages reach `Conductor::handle_message` and fall straight through to the help-string fallback at `crates/sigil-conductor/src/lib.rs:275` (`"No target session. Use /send <name> <msg> or try /help."`). Only `/status`, `/sessions`, `/check`, `/send`, `/help` actually do anything. We want plain DMs from Sebastian on Slack to land in a `vigil-slack` conductor session, plain DMs on Telegram to land in `vigil-telegram` — the per-surface conductor pattern agent-deck used (`conductor-slack-ops`, `conductor-telegram-ops`).

## Current state (what exists today)

### Bridge ingest (sigil-bridge)

- `process_slack_event` (`crates/sigil-bridge/src/slack.rs:37-87`) and `process_telegram_update` (`crates/sigil-bridge/src/telegram.rs:44-92`) are the per-platform parsers. They both:
  1. Filter event type (Slack: only `"message"`; Telegram: only updates that carry a `message`).
  2. Build the platform-specific `ActionOrigin::BridgeSlack { user_id, channel_id }` / `BridgeTelegram { user_id }`.
  3. Resolve the sender against the per-platform allowlist via `resolve_identity` (`crates/sigil-bridge/src/identity.rs:37-74`).
  4. Run `sigil_policy::normalize::normalize_text` on the body.
  5. Apply a 32 KiB size cap.
  6. Detect `is_command = text.starts_with('/')`.
  7. Stamp `ReplyContext { chat_id, channel_id }` for the reply round-trip.
  8. Hand back a `BridgeMessage` with `target_session: None`.
- `BridgeRouter::route` (`crates/sigil-bridge/src/router.rs:65-89`) gates each message through a per-user `RateLimiter` (default 30/min, 200/hr; `crates/sigil-bridge/src/rate_limit.rs`) and forwards to the configured `MessageSink`.
- The Slack adapter additionally redacts the WSS ticket from connect-error logs (`crates/sigil-bridge/src/slack_loop.rs:40-42`); the Telegram client does the same for the bot token.

### Identity allowlist + tier ceilings

- `IdentityConfig` (`crates/sigil-bridge/src/identity.rs:14-26`) is two parallel `Vec<AllowedUser>` — one per platform. Each `AllowedUser` carries `platform_id`, `display_name`, and a `tier_ceiling: Tier`.
- `build_config` (`crates/sigil-bridge/src/identity.rs:92-128`) cascades: `[bridge.<platform>]` in the project `.sigil/config.toml` → `SIGIL_<PLATFORM>_USERS` env → hardcoded defaults (Sebastian on both, Paul T1 on Slack).
- The same per-platform allowlist feeds `evaluator_config_from_identity` (`crates/sigil-cli/src/commands/bridge.rs:143-173`), which writes per-`PlatformIdentity` ceilings into `EvaluatorConfig.user_tier_ceilings`. The policy evaluator applies the override at decision time (`crates/sigil-policy/src/evaluator.rs:121-125`).

### Conductor message handling

- `Conductor::handle_message` (`crates/sigil-conductor/src/lib.rs:221-276`):
  - If the trimmed text starts with `/`, dispatch to `handle_command` (slash commands).
  - Else if `msg.target_session` is `Some`, build `Action::SendMessage`, gate it through `evaluate_and_audit` (lib.rs:297-320) — which writes an `AuditEvent` with `request_id`, `timestamp`, `action_summary`, `origin_summary`, `decision`, `session_id`, `sanitize_report` (`crates/sigil-core/src/traits.rs` + `crates/sigil-conductor/src/lib.rs:305-313`).
  - Otherwise return the help string.
- The `ConductorSink` in the CLI (`crates/sigil-cli/src/commands/bridge.rs:39-74`) wraps `handle_message`, audits a `bridge.message_routed` event, and pushes the response onto the per-bridge reply mpsc.
- Replies travel back via `mpsc<(ReplyContext, String)>` and the per-platform send (`crates/sigil-bridge/src/telegram_loop.rs:86-95`, `crates/sigil-bridge/src/slack_loop.rs:159-168`).

### What's missing

1. No mapping from "this DM came from Slack/Telegram" to "deliver to session X." The bridge has no way to express it, and the conductor has nowhere to look it up.
2. The conductor has no concept of a per-surface default destination; `target_session` is the only knob and only `/send <name> <msg>` populates it.
3. The reply path normalizes nothing on the way out (the body the conductor assembles can include arbitrary text).
4. There is no defense against bot-authored events looping back into the bridge (Slack `bot_id`, Telegram `from.is_bot`).

> **Codex Pass 1:** Codex pushed back on five fronts before I drafted the Design section: `get_session_by_title` is the weakest link (TOCTOU on rename/delete); session identity files (`SOUL.md`, `OPS.md`, `LEARNINGS.md`) become a fresh attack surface for routed DMs; anti-loop / bot-event filtering and per-surface aggregate caps are missing; reply egress should be normalized + truncated; and a separate `SurfaceRoutingConfig` type would duplicate `BridgePlatformConfig`. All five are folded into the Design section below.

## Design

### Routing model

**1:1 surface → session, configured once, resolved once at startup.**

Add a single optional field to the existing per-platform config block:

```toml
# .sigil/config.toml — appended to the per-platform sections that already exist
[bridge.slack]
default_session = "vigil-slack"      # NEW

[bridge.telegram]
default_session = "vigil-telegram"   # NEW
```

The corresponding env-var equivalents (mirroring the existing `SIGIL_<PLATFORM>_USERS` pattern) are `SIGIL_SLACK_DEFAULT_SESSION` and `SIGIL_TELEGRAM_DEFAULT_SESSION`. Same precedence: file → env → unset.

The bridge **runner** in `sigil-cli` (the only place with both `Store` and the per-platform config in scope) does the title → `SessionId` lookup once at startup. The result is a typed table:

```rust
// crates/sigil-conductor/src/lib.rs (new type, added next to Conductor)
#[derive(Clone, Debug, Default)]
pub struct BridgeRouting {
    /// Where Slack DMs land. None = no default route configured.
    pub slack: Option<SessionId>,
    /// Where Telegram DMs land.
    pub telegram: Option<SessionId>,
}

impl Conductor<R> {
    #[must_use]
    pub fn with_bridge_routing(mut self, routing: BridgeRouting) -> Self {
        self.bridge_routing = routing;
        self
    }
}
```

`handle_message` adds one new branch *before* the existing "no target" fallback:

```text
if text.starts_with('/')               → handle_command (unchanged)
else if msg.target_session.is_some()   → SendMessage to msg.target_session (unchanged)
else if let Some(sid) = routing.for_origin(&msg.origin)
                                       → SendMessage to sid (NEW)
else                                   → help string (unchanged)
```

`BridgeRouting::for_origin` is a 4-line match:

```rust
pub fn for_origin(&self, origin: &ActionOrigin) -> Option<SessionId> {
    match origin {
        ActionOrigin::BridgeSlack { .. }    => self.slack,
        ActionOrigin::BridgeTelegram { .. } => self.telegram,
        _ => None,
    }
}
```

Two structural choices worth making explicit:

1. **Routing key is the `ActionOrigin` discriminant**, never message text. The discriminant is set inside `process_slack_event` / `process_telegram_update` from the platform-specific event type, before any user-controlled bytes are inspected. A Slack DM cannot be coerced into the Telegram bucket.
2. **Title is resolved exactly once, fail-closed.** If the configured title is missing or ambiguous at bridge startup, the runner refuses to start the bridge and surfaces the exact mismatch (`"slack default_session 'vigil-slack' not found in store"`). No silent fallback to "no target." This closes Codex's TOCTOU finding: there is no per-message title lookup, so rename/delete after startup cannot redirect traffic.
3. **No change to the `BridgeMessage` protocol shape.** The new field lives on `Conductor`, not on the wire. An ingress-controlled `target_session` field would be a weak trust boundary; the routing decision stays inside the control-plane.

### Identity propagation

The `ActionOrigin::BridgeSlack { user_id, channel_id }` / `BridgeTelegram { user_id }` already in `BridgeMessage.origin` is what `Conductor::handle_message` clones into the new `Action::SendMessage`'s `ActionRequest`. End-to-end this means:

```text
Slack event (user=U_PAUL, channel=C_GEN, text="…")
  → process_slack_event:
       origin = BridgeSlack { user_id: "U_PAUL", channel_id: "C_GEN" }
       target_session: None
  → BridgeRouter (rate-limit per "slack:U_PAUL")
  → ConductorSink::accept
  → Conductor::handle_message
       routing.for_origin(&origin) = Some(vigil_slack_id)
       ActionRequest {
         action:  SendMessage { session_id: vigil_slack_id, message: text }
         origin:  BridgeSlack { user_id: "U_PAUL", channel_id: "C_GEN" }
       }
  → PolicyService::evaluate (resolves Paul → T1 ceiling)
  → AuditLogWriter.append (origin_summary preserves BridgeSlack { … })
  → runtime.send(handle, TaskAssignment { instructions: text })
  → reply_tx.send((ReplyContext { channel_id: Some("C_GEN") }, response))
  → SlackBridge sends `response` back to C_GEN
```

The user's identity rides every hop in `ActionOrigin`, and the audit entry preserves it verbatim alongside the destination `session_id`. The conductor session itself, when *it* later acts (e.g. spawns a child session via MCP), runs as `ActionOrigin::AgentGenerated { session_id: vigil_slack_id }` — that is its own principal, distinct from Paul's, with its own T1 ceiling per `crates/sigil-core/src/principal.rs:151-160`.

### Tier handling

Two tiers are in play and must not be conflated:

| Hop | Origin used | Ceiling that applies |
|---|---|---|
| Bridge DM → `Action::SendMessage` to `vigil-slack` | the user's `BridgeSlack`/`BridgeTelegram` | the user's `tier_ceiling` from the platform allowlist (Paul T1, Sebastian T3) |
| `vigil-slack` agent generates an action via MCP | `ActionOrigin::AgentGenerated { session_id: vigil_slack_id }` | T1 (the default for agent origins, `principal.rs:151-160`) |

`SendMessage` requires `Capability::SendMessage` → `Tier::T1` (`crates/sigil-core/src/action.rs:230` and `crates/sigil-core/src/trust.rs`). Paul T1 ⇒ `Allow`. Sebastian T3 ⇒ `Allow`. A revoked principal ⇒ `Deny` (existing behavior at `evaluator.rs:128-132`). A ceiling that has been degraded to `T0` ⇒ `Deny`. **The routing change adds no new authority** — it only makes an existing policy-gated action reachable from a per-surface default destination instead of `/send <name> <msg>`.

### Audit trail

Every routed message produces:

| Step | Event | Fields | Source of truth |
|---|---|---|---|
| 1. Bridge accepts envelope | `bridge.message_routed` | `text_len`, `origin: ActionOrigin`, `target: Option<SessionId>` | `crates/sigil-cli/src/commands/bridge.rs:62-71` (existing) |
| 2. Conductor evaluates `SendMessage` | `AuditEvent` | `request_id`, `timestamp`, `action_summary` (`SendMessage { session_id: vigil_slack_id, … }`), `origin_summary` (the user's `BridgeSlack { … }`), `decision` (Allow/Deny/NeedsApproval), `session_id: Some(vigil_slack_id)`, `sanitize_report: None` | `crates/sigil-conductor/src/lib.rs:297-320` (existing) |
| 3. Runtime delivers the `TaskAssignment` | (no audit event today; relies on episode capture) | episode `BridgeSend { session_id, title }` if memory is configured | `crates/sigil-conductor/src/lib.rs:257-262` (existing) |
| 4. Conductor's response sent back via reply channel | **NEW** `bridge.reply_sent` | `target_origin` (the original user's `BridgeSlack`/`BridgeTelegram`), `text_len`, `truncated: bool`, `session_id: Some(vigil_slack_id)` | new `log_event` call in `ConductorSink::accept` after `reply_tx.send` |

Step 4 is the only addition. Today the bridge silently sends responses back; the new event closes the loop on "every routed message must be auditable end-to-end" so an investigator can replay a DM from accept → conductor decision → runtime delivery → reply.

### Egress sanitization on the reply path

Per Codex Pass 1, the conductor's `response` string is currently passed to `reply_tx.send` unmodified. We add a thin egress filter at the `ConductorSink` boundary (the only place where the reply leaves the control-plane):

1. Run `sigil_policy::normalize::normalize_text` on the response (same primitive bridge ingress already uses) — strips invisible/zero-width/directional-override characters that an upstream agent could have inserted as a covert channel back to the human.
2. Truncate at 4 KiB with a visible `… [truncated, N bytes]` suffix. Telegram's per-message limit is 4096 chars; Slack tolerates more but long messages are a stego/exfil amplifier and a UX problem either way.
3. Stamp `truncated: bool` and the original byte count into the new `bridge.reply_sent` audit event.

### Anti-loop / bot-event filtering at ingress

Per Codex Pass 1, ignore bot-authored events at the platform parsers — these are the cheapest way for a compromised conductor to talk to itself in a tight loop:

- `process_slack_event` returns `Ok(None)` if the Slack event has `bot_id` set, or `subtype == "bot_message"`. (Today the parser does not look at either field; we add them to the small `EventPayload` struct in `slack_loop.rs` and the `SlackEvent` it builds.)
- `process_telegram_update` returns `Ok(None)` if `message.from.is_bot == true`. (Same: not currently extracted; one new optional bool on `TelegramMessage`.)

Both checks fire **before** allowlist resolution, so a bot impersonating an allowlisted user is dropped and not even rate-limited (no per-bot quota burned).

## Security analysis

For each relevant trap class from `docs/AGENT-TRAPS-DEFENSE.md` and `docs/STEGO-DEFENSE.md`, plus three new threats specific to routing.

| Trap / threat | Vulnerable? | Mitigation in this design |
|---|---|---|
| **Web-Standard Obfuscation** (TRAPS §1) — hidden HTML/aria/comments in fetched content | N | Out of scope; covered by `sigil-content` for `Action::FetchExternalContent`. Routing change does not touch the fetch path. |
| **Steganographic Payloads** in media (TRAPS §1) | N | Out of scope; routing handles text only. |
| **Syntactic Masking** in formatting (TRAPS §1) | N (no regression) | Existing `normalize_text` runs at bridge ingest; routing reuses the same normalized `BridgeMessage.text`. |
| **Latent Memory Poisoning** (TRAPS §3) | **Y, real — not mitigated in PR A/B; PR C scope** | A routed DM becomes a `TaskAssignment` the conductor session reads into context. If memory is configured, an episode is appended for every bridge send (`crates/sigil-conductor/src/lib.rs:257-262`). **A `routed_via` tag on this episode would not actually quarantine durable promotion: `record_bridge_send` writes an `EpisodeKind::ActionCompleted` episode (`crates/sigil-conductor/src/memory.rs:133-152`), while consolidation only promotes `EpisodeKind::CandidateLearning` events (per `sigil-memory::consolidator`).** The real enforcement point is `CandidateLearning` provenance — annotating those events when the originating context contains bridge-routed input, and filtering at promotion time. That requires understanding how `CandidateLearning` events are minted today and is deferred to **PR C**, which lands the actual mechanism. PR A/B do not weaken existing memory defenses (no tier elevation), but they also do not add new ones. |
| **Sub-agent Spawning Traps** (TRAPS §4) | N (no regression) | The conductor session uses `ActionOrigin::AgentGenerated { session_id: vigil_slack_id }`. Spawning a child session is a `T1` `Action::CreateSession` (`action.rs:222-228`) gated by `evaluate_and_audit`. Custom prompts containing the original DM body are still subject to existing Action enum + tier enforcement. |
| **Approval Fatigue** (TRAPS §6) | **Y, real** | Routing means a single Slack user can stream messages into one conductor session at the per-user `RateLimiter` ceiling (30/min). If that conductor session generates approval requests in response, the operator sees a synthesized burst. Mitigation: existing `FatigueGuard` (`crates/sigil-policy/src/fatigue.rs`) already gates T2+ approvals from rate-burning. We do **not** raise the per-user rate limit. We add a follow-up watch item: per-surface aggregate cap (queue depth into `vigil-slack`) — captured as a Phase 2 item below. |
| **Automation Bias** (TRAPS §6) | N (no regression) | The routing change does not summarize anything for the operator differently from today. |
| **Text/Unicode stego** (STEGO §1) on inbound DM | N | `normalize_text` runs at bridge ingest, before routing. |
| **Text/Unicode stego on the reply path** | **Y, real** | Today the conductor's response goes back through the bridge unmodified. **NEW:** `ConductorSink` runs `normalize_text` on the response and truncates at 4 KiB before `reply_tx.send` (see Egress sanitization above). |

### New threats specific to routing

| Threat | Vulnerable? | Mitigation |
|---|---|---|
| **R1. Title→ID drift / TOCTOU.** Operator renames/deletes `vigil-slack` between bridge startup and a DM. Per-message title lookup would either fall through to the help string or, worse, race with a malicious rename to a different session. | N | Title resolved **once** at bridge startup to `SessionId`. After startup the SessionId is opaque and immutable. If the session is later removed, `runtime.send` returns `ConductorError::Internal` → user-facing string surfaces the failure. **Note on audit semantics:** the policy `Allow` has already been written to the audit log by `evaluate_and_audit` (`crates/sigil-conductor/src/lib.rs:242`) *before* the runtime call (`lib.rs:250`); a runtime failure does **not** produce a synthetic `Deny` event. The audit log shows `Allow` followed by no further policy events — the failure is detectable by the absence of a corresponding episode and by a `tracing::warn` from `ConductorSink`. PR B should add a `bridge.send_failed` event in the same `ConductorSink::accept` path that already audits `bridge.message_routed`, so investigators see both the policy verdict and the runtime outcome on the same correlation key. No per-message title lookup path exists, so the original TOCTOU is closed; this is a separate audit-completeness gap that PR B closes. |
| **R2. Surface spoofing.** Slack DM gets routed to `vigil-telegram`. | N | Routing key is the `ActionOrigin` discriminant, set inside the platform parser from the platform-specific event type, never from message text. The match in `BridgeRouting::for_origin` is exhaustive on `BridgeSlack` / `BridgeTelegram`. |
| **R3. Bot-event self-loop.** Conductor session posts back to Slack via MCP; Slack delivers the bot-authored message; bridge re-ingests it; conductor re-routes; loop. | N | Bot-event filter at the platform parser drops `bot_id` / `is_bot` events before allowlist resolution (see Anti-loop section). |
| **R4. Identity-files-as-attack-surface.** A routed DM body is now the most direct way to push attacker-controlled text into the `vigil-slack` agent's context, where `SOUL.md` / `OPS.md` / `LEARNINGS.md` define behavior. Indirect injection in the DM tries to influence those reload loops. | **Y, partial** | The `IdentitySpec` reload loop is an **instruction sent to the agent** to re-read named files from disk (`crates/sigil-cli/src/commands/identity.rs:112`); it is not enforced read semantics — the agent can be instructed not to re-read, or to re-read different files. So this is a behavioral defense, not a structural one. Direct overwrite of `SOUL.md` requires `Action::WriteHostFile` (T3 capability per `crates/sigil-core/src/trust.rs:82`); an `AgentGenerated` principal is capped at T1, so direct overwrite from the conductor session itself is denied. A `HumanApproved` path (Sebastian explicitly approves a T3 write) could still happen — that is the same residual today's `/send` already has; routing does not widen it. The *new* contribution is making the channel low-friction enough that we should explicitly note the concern in OPS.md so the human reviewer knows to be skeptical of `vigil-slack`'s LEARNINGS.md proposals (the recurrence-3+ rule was already there for a reason). |
| **R5. Per-surface DoS into one session.** A burst from an allowlisted user with a high `tier_ceiling` could fan messages into a single conductor session faster than it can process them. | **Y, partial** | Per-user `RateLimiter` (30/min, 200/hr) caps fan-in. The mpsc reply channel has bounded capacity (`REPLY_CHANNEL_CAPACITY = 64` in `bridge.rs:29`); back-pressure surfaces as `tracing::warn!` today. Phase 2: track per-surface aggregate queue depth into the conductor session and back-pressure new `SendMessage` evaluations once the session's last 60s of inbound messages exceeds N. |

## Files to modify

| File | Change | Why |
|---|---|---|
| `crates/sigil-core/src/config.rs` | Add `default_session: Option<String>` to `BridgePlatformConfig` (per-platform). | Single canonical config knob, lives next to the existing per-platform allowlist block. |
| `crates/sigil-bridge/src/identity.rs` | Surface the `default_session` value through `IdentityConfig` as two new optional fields: `slack_default_session: Option<String>`, `telegram_default_session: Option<String>`. Same cascade as users (file → env → unset). | Keeps a single config-loader for the whole `[bridge.<platform>]` block. No new abstraction. |
| `crates/sigil-bridge/src/slack.rs` | Add `bot_id: Option<String>`, `subtype: Option<String>` to `SlackEvent`. Filter `bot_id.is_some() \|\| subtype.as_deref() == Some("bot_message")` → return `Ok(None)`. | R3 mitigation (anti-loop). |
| `crates/sigil-bridge/src/slack_loop.rs` | Pull `bot_id` and `subtype` out of `EventPayload` into the `SlackEvent` it builds (`slack_loop.rs:269-275`). | Plumbing for the parser change. |
| `crates/sigil-bridge/src/telegram.rs` | Add `from_is_bot: bool` to `TelegramMessage`. Filter `from_is_bot == true` → return `Ok(None)`. | R3 mitigation (anti-loop). |
| `crates/sigil-bridge/src/telegram_client.rs` (or wherever the long-poll JSON is decoded) | Decode `message.from.is_bot` from the Telegram update payload. | Plumbing. |
| `crates/sigil-conductor/src/lib.rs` | Add `BridgeRouting { slack: Option<SessionId>, telegram: Option<SessionId> }` type and `with_bridge_routing` builder; add the new branch in `handle_message` between the `target_session.is_some()` arm and the help-string fallback; tag bridge-routed episodes with `routed_via` (R4 partial mitigation for memory quarantine). | Single canonical routing table consumed by the conductor. |
| `crates/sigil-conductor/src/memory.rs` (`record_bridge_send`) | Extend the captured episode to record the originating `BridgeSurface` so consolidation policy can quarantine. | R4 / latent memory poisoning. |
| `crates/sigil-cli/src/commands/bridge.rs` | After `load_identity_config`, call new `load_bridge_routing(&store, &identity)` that resolves each configured title → `SessionId` (fail-closed if missing). Pass the resulting `BridgeRouting` to `Conductor::with_bridge_routing` before the bridge is started. Wrap conductor responses with `normalize_text` + 4 KiB truncate inside `ConductorSink::accept`. Audit `bridge.reply_sent` and `bridge.send_failed`. | Wires routing in at the only place that has both `Store` and `IdentityConfig` in scope; adds the egress filter and the two new audit events. |
| `crates/sigil-cli/src/lib.rs` (`Commands::Bridge` arm at `:672`) | After `load_identity_config` + `evaluator_config_from_identity`, also call `load_bridge_routing` and chain `.with_bridge_routing(routing)` onto the `Conductor::new` builder at `:679-685`. | The `sigil bridge` subcommand has its own conductor-construction site; without this the bridge path skips routing. |
| `crates/sigil-cli/src/commands/run.rs` (`:60-78`) | Mirror the same change inside the `bridge_mode.is_some()` branch: load routing, chain `.with_bridge_routing(routing)` onto `conductor_builder`. | `sigil run --bridge` is the second conductor-construction site; routing must apply consistently across both entry points. |
| **Test fallout** (compile-only churn from new optional struct fields) | `BridgePlatformConfig` literal sites in `sigil-core` config tests and `sigil-bridge` identity tests; `TelegramMessage` literal sites in `sigil-bridge` + CLI integration tests; `SlackEvent` literal sites in `sigil-bridge` + CLI integration tests. | New `Option<String>` / `Option<bool>` fields will need `..Default::default()` or explicit defaults at every literal construction. Touch surface is wider than the four "real" files above. |

## Files to add

None. Every change fits the existing crate boundaries. The single new type (`BridgeRouting`) lives next to `Conductor` because it is consumed by `handle_message`.

## Phased rollout

Codex Pass 2 flagged a single mega-PR as too high blast-radius; the work splits cleanly into three independently-shippable PRs.

- **PR A — Anti-loop + egress hardening (no routing dependency, hardens today's code).**
  - Bot-event filter at both platform parsers (R3): Slack `bot_id` / `subtype: bot_message` and Telegram `from.is_bot`.
  - `normalize_text` + 4 KiB truncate on the reply path inside `ConductorSink::accept`; new `bridge.reply_sent` audit event.
  - Tests for both bot-filter cases, the reply-truncation roundtrip, and the new audit event shape.
  - **Why first:** lands defensive value even if PR B is delayed or reverted. Doesn't depend on routing existing. Also keeps PR B's diff focused on the routing decision itself.

- **PR B — Surface routing + startup resolution + audit semantics.**
  - `BridgePlatformConfig.default_session`; cascade through `IdentityConfig` (file → env → unset).
  - `BridgeRouting` type + `Conductor::with_bridge_routing` builder + the new branch in `handle_message`.
  - `load_bridge_routing` in `sigil-cli` with fail-closed startup resolution; wire into both `Commands::Bridge` arm and `sigil run --bridge`.
  - `bridge.send_failed` audit event in `ConductorSink::accept` so runtime-send failures after `Allow` are observable on the same correlation key as `bridge.message_routed` (closes R1's audit-completeness gap).
  - Tests: per-surface routing, surface-spoofing negative, fail-closed missing-session, deny-on-revoked-principal still works, runtime-send-failure-after-Allow audit semantics, env precedence for `default_session`, both `sigil bridge` and `sigil run --bridge` paths exercise routing.

- **PR C — Memory provenance / quarantine (deferred until we define the real enforcement point).**
  - Identify how `EpisodeKind::CandidateLearning` events are minted and tag them with `routed_via: BridgeSurface` when the originating context contains bridge-routed input.
  - Filter promotion at the consolidator using the new tag.
  - Per-surface aggregate cap into a single destination session (R5) — track per-`SessionId` inbound rate; back-pressure `BridgeRouting` resolution when the destination's recent traffic exceeds N. Only valuable once multiple allowlisted users routinely share a surface.
  - Out of scope until then: the per-user `RateLimiter` (30/min, 200/hr) already bounds the worst case for the daily Sebastian-only usage pattern.

## Migration from current state

- **Vigil's cutover (one-time, all on the operator's side):**
  1. `sigil session launch ~/.vigil-vault -t vigil-slack -c claude -g vigil -m "<initial bootstrap prompt>"` (and `-t vigil-telegram` for the other surface). **Use `launch`, not `create`.** `session create` produces a `Stopped` record; routed sends to a `Stopped` session will fail at the runtime layer (per `crates/sigil-conductor/src/action_service.rs:446`). `launch` creates + starts the tool in one call (post-PR #59 readiness wait, per `docs/migration-friction.md:226-235`).
  2. Wait for the readiness ack from each session (one-line `READY` ping or equivalent) before relying on routing.
  3. Append two lines to `.sigil/config.toml`:
     ```toml
     [bridge.slack]
     default_session = "vigil-slack"
     [bridge.telegram]
     default_session = "vigil-telegram"
     ```
  4. Restart `sigil bridge all` (or per-surface). The runner does the title→ID resolution at startup; if either configured session is missing, it fails closed with the exact mismatch printed.
- **Operational caveat — rate limits are per-bridge, not per-conductor.** The `RateLimiter` lives inside each `BridgeRouter` (`crates/sigil-bridge/src/router.rs:30-50`). Slack and Telegram each have their own; routing into a single conductor session does **not** share rate-limit state across surfaces. A user who is allowlisted on both surfaces could in principle send 30/min on each, fanning 60/min into the same `vigil-*` session. PR C (per-surface aggregate cap into a single destination) addresses this when it lands.
- **Operators who do not set `default_session`:** behavior is byte-identical to today — non-command DMs still hit the help-string fallback. The new code paths are opt-in.
- **No DB migration.** Routing state lives in config + in-memory `BridgeRouting`; no schema change.
- **Slash commands unaffected.** `/status`, `/sessions`, `/check`, `/send`, `/help` continue to work exactly as today.

## Testing strategy

Tests are grouped by PR (matching the rollout split in §Phased rollout) so each PR's review surface is self-contained.

### PR A (anti-loop + egress)

- **`sigil-bridge` unit tests:**
  - Slack event with `bot_id` set → `process_slack_event` returns `Ok(None)`.
  - Slack event with `subtype: "bot_message"` → `Ok(None)`.
  - Telegram update with `message.from.is_bot = true` → `process_telegram_update` returns `Ok(None)`.
  - Bot-event filter fires before allowlist resolution (no allowlist hit recorded).
- **`sigil-cli` unit tests on `ConductorSink::accept`:**
  - Response containing zero-width chars → emitted reply has them stripped via `normalize_text`.
  - Response longer than 4 KiB → emitted reply ends with `… [truncated, N bytes]`; `truncated: true` in the audit event; `N` matches the original byte count.
  - Response shorter than 4 KiB → no truncation suffix; `truncated: false`.

### PR B (routing + audit semantics)

- **`sigil-bridge` unit tests:**
  - `IdentityConfig::slack_default_session` parses out of `[bridge.slack].default_session` in TOML config.
  - Same value parses out of `SIGIL_SLACK_DEFAULT_SESSION` env when the config block is absent (env precedence).
  - When both are set, config wins (file > env, mirroring the existing user-allowlist cascade).
  - `default_session` unset in both → `None` (regression: today's behavior unchanged).
- **`sigil-cli` unit tests:**
  - `load_bridge_routing` with a configured title that exists in the store → `BridgeRouting { slack: Some(sid), … }`.
  - `load_bridge_routing` with a configured title that is missing → returns an error containing both the platform name and the missing title (fail-closed).
- **`sigil-conductor` unit tests:**
  - `handle_message` with `BridgeSlack` origin + no `target_session` + `BridgeRouting { slack: Some(sid), … }` → builds `Action::SendMessage { session_id: sid, … }`, returns "Message sent to …".
  - Same with `routing.slack = None` → returns the existing help string (regression guard for opt-in behavior).
  - `BridgeTelegram` origin only ever resolves `routing.telegram` even when `routing.slack` is `Some` (cross-surface integrity / R2).
  - `BridgeSlack` origin with `routing.slack = Some(sid)` but the runtime returns an error from `send` → `ConductorError::Internal` propagates, surfaces as a clear user-facing string, and writes a `bridge.send_failed` audit event (R1 audit completeness).
  - Paul-tier (T1) DM → `SendMessage` evaluates `Allow` (T1 capability). Revoked principal → `Deny`. Tier-ceiling-degraded principal → `Deny`.
- **Integration test (`crates/sigil-cli/tests/`, tmux-gated like UC9/UC10 — run with `cargo test -- --ignored` per `CLAUDE.md`):**
  - End-to-end: pre-launch a session named `vigil-slack`, configure `default_session = "vigil-slack"`, fire a synthetic Slack `message` envelope through the in-process bridge.
  - Assert: `TaskAssignment` lands in the runtime; audit log shows `SendMessage { session_id: vigil_slack_id, … }` with `origin_summary` containing `BridgeSlack { user_id: …, channel_id: … }`; `bridge.reply_sent` audit entry follows; correlation key links accept → policy → reply.
  - Repeat the smoke through `sigil run --bridge` (the second conductor-construction site) to prove routing applies on both entry points.
- **Out of scope:** audit-chain HMAC regression tests for the new event types are *not* required — the chain machinery is event-type-agnostic; existing chain tests cover any new payload that round-trips through `AuditEvent`. Only add a new chain test if the event shape introduces a non-Serialize field, which it does not.

### PR C (memory provenance)

- Tests defined when the enforcement point is concrete; not in scope here.

## Estimated effort

- **PR A** — implementation ~2 h, testing ~1 h.
- **PR B** — implementation ~5 h (~2 conductor routing-table + branch, ~2 cli wiring + dual entry points, ~1 plumbing/config), testing ~2.5 h (unit + the gated integration test on both entry points).
- **PR C** — sized once the `CandidateLearning` mint sites are mapped; rough placeholder ~4 h impl + 1 h test.
- **Per-bridge cutover for Vigil** — ~10 minutes: two `session launch` calls + readiness wait + two `.sigil/config.toml` lines + `sigil bridge all` restart. (Earlier "5 minutes" estimate ignored launch + readiness, per Codex Pass 2.)

## Open questions for Sebastian

1. **Behavior when the configured destination is `Stopped` or `Error` at DM time.** Three options:
   - (a) Attempt `SendMessage` anyway, let `runtime.send` fail, surface as "vigil-slack is unreachable, message not delivered." `bridge.send_failed` lands in audit.
   - (b) Pre-check `SessionState` in `handle_message` and refuse early with a different user-facing string.
   - (c) Pre-check + auto-issue `Action::StartSession` (T1) for `Stopped`, refuse for `Error`.
   - **Recommendation: (a).** Single code path, audit captures the failure consistently with how `/send` already handles unreachable sessions, no new policy decisions implied. (c) is tempting but expands the implicit-action surface — operator should explicitly start a stopped conductor session.
2. **Reply truncation cap of 4 KiB.** Telegram per-message is 4096 chars; Slack tolerates more but long replies are bad UX and a stego/exfil amplifier. Confirm 4 KiB, or pick a different number.

**Decided defaults (override at implementation time if you want):**

- *Naming:* `vigil-slack` / `vigil-telegram`. Mirror's agent-deck's pattern; matches the brief.
- *Egress normalize + truncate:* `normalize_text` from `sigil-policy` (already in use at ingest) + 4 KiB hard cap with `… [truncated, N bytes]` suffix.
- *Bot-event filter:* drop before allowlist resolution so impersonating bots don't burn quota.

## Rejected alternatives

- **Routing field on `BridgeMessage`.** Rejected. The bridge is `Ingress`; any field on `BridgeMessage` is influenced by the platform-specific event payload and is a weaker trust boundary than control-plane config. Routing decisions belong on the conductor side.
- **Per-message `get_session_by_title` lookup.** Rejected. TOCTOU on rename/delete (Codex Pass 1); also a small per-message latency tax and a per-message DB hit. Resolve once at startup; fail closed.
- **Env-var-only routing (no `[bridge.<platform>].default_session`).** Rejected. Existing identity allowlist is config-first with env fallback for portability — routing should follow the same pattern so an operator inspecting `.sigil/config.toml` sees the full picture without grepping environment.
- **Per-user routing overrides** (e.g. Paul → `paul-slack`, Sebastian → `vigil-slack`). Deferred to Phase 2 / future. The current single-operator-plus-occasional-collaborator usage pattern doesn't justify the lifecycle/config sprawl. The single per-surface default covers the daily case; per-user routing can be added later without breaking the per-surface contract.
- **Fanout / multicast** (one DM → many sessions). Rejected up front per the brief and per KISS. 1:1 only.
- **Auto-launch the configured destination session on bridge startup** if it's missing. Rejected. Implicit session creation hides operator intent and complicates the reverse case (operator removed the session deliberately). Fail-closed at startup with a clear error, and let the operator run `sigil session launch` themselves.
- **Per-conductor allowlists** (e.g. `[bridge.slack.routes.vigil-slack].allowed_users = […]`). Considered (Codex argued both sides). Rejected for Phase 1 because the existing per-user `tier_ceiling` already gates what each user can cause to happen; adding a second allowlist layer is config sprawl with no defense the tier-ceiling layer doesn't already give. Revisit if/when more than two users are routinely allowed on a surface.
- **Separate `SurfaceRoutingConfig` type alongside `IdentityConfig`.** Rejected (Codex Pass 1 KISS finding). The field lives on the existing `BridgePlatformConfig` and surfaces through `IdentityConfig` directly; the conductor consumes a single typed `BridgeRouting` table. One canonical routing table, not two parallel ones.

> **Codex Pass 2:** Codex flagged six concrete realism gaps after reading the full draft, all folded in above:
> 1. **Memory-quarantine claim was wrong.** `record_bridge_send` writes `EpisodeKind::ActionCompleted` (`crates/sigil-conductor/src/memory.rs:133-152`) while consolidation only promotes `EpisodeKind::CandidateLearning` — tagging bridge-send episodes does nothing. Demoted from "Phase 1 partial mitigation" to **PR C with a real enforcement point** (annotate `CandidateLearning` mint sites by provenance).
> 2. **R1 audit semantics overstated.** The policy `Allow` is written *before* `runtime.send` (`crates/sigil-conductor/src/lib.rs:242` then `:250`); a runtime failure does not back-fill a `Deny`. PR B now adds a `bridge.send_failed` audit event in `ConductorSink::accept` to close the audit-completeness gap on the same correlation key as `bridge.message_routed`.
> 3. **Identity-reload-from-disk wording was structural-sounding but is behavioral.** The reload is an instruction message to the agent (`crates/sigil-cli/src/commands/identity.rs:112`), not enforced read semantics. R4 rewritten to acknowledge that the structural defense is the T3 capability gate on `Action::WriteHostFile`, not the reload mechanism.
> 4. **Files-to-modify table was missing two conductor-construction sites:** `Commands::Bridge` arm in `crates/sigil-cli/src/lib.rs:672` and `sigil run --bridge` in `crates/sigil-cli/src/commands/run.rs:60-78`. Both must be touched or routing applies inconsistently. Added explicitly.
> 5. **Phase 1 was overloaded** (routing + bot-filter + egress + memory + new audit + multi-crate tests in one PR). Re-split into **PR A (anti-loop + egress, no routing dep)**, **PR B (routing + audit semantics)**, **PR C (memory provenance)**.
> 6. **Migration "5 minutes" was optimistic.** `session create` produces `Stopped` records; routed sends fail until the session is actually launched. Updated to use `session launch` + readiness wait + noted that `RateLimiter` is per-bridge, not shared through the conductor.
>
> Test-plan additions Codex called for are also folded in: env precedence for `default_session`, runtime-send-failure-after-Allow audit semantics, both `sigil bridge` and `sigil run --bridge` entry points exercised. Audit-chain regression test was downgraded — chain code is event-type-agnostic.
