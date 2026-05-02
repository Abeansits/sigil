# Production Readiness — Retire agent-deck, Run Vigil on Sigil

**Status:** drive doc for the Vigil→Sigil migration
**Date:** 2026-05-01
**Author:** Vigil (ops conductor), consolidating prior analysis from `state.json` + `WORKQUEUE.md` + `FEATURE-AUDIT.md`

---

## What "production-ready" means here

Lower bar than enterprise. "Production" = **Sebastian's daily-driver replacement for agent-deck**, not a product for external users. The test is dogfooding: can Vigil run under Sigil for 48 hours with zero rollback events? If yes, ship. If no, fix what broke.

Sebastian's framing from the 2026-04-19 decision: *"hobby project that supports ourselves first — lower bar than production-grade; faster to ship imperfect-but-useful."*

The migration retires one piece of infra (agent-deck — Rust+tmux session orchestration, 2yr-old Python bridge, launchd jobs) and replaces it with a coherent one (sigil — single Rust workspace, 11 crates, same substrate).

## Where we are

**Code complete** (merged to `main`, 2026-04-08 → 2026-04-19):

- Session lifecycle: create / launch / start / stop / restart / send / output / remove / list / show
- tmux integration + status reconciliation + ANSI stripping
- Worktrees: create / list / finish / optional-merge / safe branch cleanup
- Policy: typed actions, trust zones, tier ceilings, FatigueGuard, approval grants (SQLite)
- Audit: HMAC-chained JSONL, Keychain-backed key, `sigil audit verify`
- Bridges (library): Telegram long-poll + Slack Socket Mode + identity resolution + rate limiting + `sigil bridge {telegram,slack,all}` CLI
- MCP server (`sigil-mcp`): host-side policy-mediated tool surface for agents
- Content sanitization Phase 1: 7 PRs (#43, #45, #52–#58), 5-stage pipeline (plain/html/markdown/json), `SanitizeReport` wired through `ActionResult`, conductor runs sanitizer on external-content results
- Container runtime (feature-gated)
- Memory Phase 1: operational lifecycle triggers + episode kinds
- ActionService: unified policy pipeline (PR #37, #41)
- 11 crates, 600+ tests, binary at `~/.cargo/bin/sigil`

**Surface parity with agent-deck: ~95%** (per `FEATURE-AUDIT.md`, 2026-04-08, + subsequent PRs).

## What's missing for daily-driver swap

### 1. Group + parent-session CLI exposure — **shipped (PR #61)**
`sigil session set-group <id> <group>` and `sigil session set-parent <id> <parent-id>` land the management commands; `parent_title` is rendered in `session show --json`. Closes the heartbeat-linkage gap.

### 2. Policy-driven auto-response (medium) — **still open**
Conductor loop has heartbeat + reconciliation + bridge-style command handling. Not yet exposed: **multi-conductor management** (one conductor per profile/channel) and **policy-driven auto-response** (rules for when conductor auto-replies vs escalates). Today this logic lives in Vigil's prompt (OPS.md § auto-response policy). Moving it into Sigil makes it testable.

Likely shape: a `sigil conductor policy` subcommand + a YAML/TOML rule file. Lower priority — Vigil's prompt-layer policy works fine for now.

### 3. Heartbeat durability (cron → launchd) — **still open**
Current heartbeat uses Claude Code's `CronCreate` — **session-only, 7-day auto-expire**. When the conductor session restarts (or after 7 days), heartbeat stops. `durable: true` doesn't actually persist to disk (known bug).

Need: launchd plist(s) firing a shell script → `sigil session send conductor-ops "<prompt>"`. Separately queued under Infra. Prerequisite for Phase D (migrating Vigil itself).

### 4. `session send` semantics parity — **shipped (PRs #62, #63)**
`sigil session send <id> "msg" --wait -q --timeout 300s` matches the agent-deck shape. `--timeout` rejected without `--wait` (one-line guard, PR #63).

### 5. `session launch` worktree ergonomics — **shipped (PR #60)**
`sigil session launch <path> --title "Title" --tool claude --worktree feature/branch -b` runs the compound launch + worktree + branch flow in one call.

### 6. Error-message clarity under tool misbehavior — **partially mitigated**
TmuxRuntime input-delivery reliability fixed (PR #59) and `--json` stdout stays pure (PR #64). Live error-shape regressions only surface under real load — keep the Phase A friction log running through Phase D as the primary signal.

## What's explicitly **not** needed

From `FEATURE-AUDIT.md`, these are out of scope for this migration:

- Profiles / TUI / Web UI / WebSocket / push notifications
- SSH remote execution / multi-machine instance management
- Cost tracking and budget UI
- OpenClaw integration
- Hook install/uninstall command set
- Interactive attach, automatic tmux-session detection, rename, fork/clone, per-session notes

If Sigil doesn't have them today and Vigil doesn't use them, they stay off the critical path.

## Migration plan (5 phases)

Expected: **3–5 small PRs**, not a 10-PR epic.

### Phase A — Solo smoke test (autonomous, low-stakes) — **DONE 2026-05-01**
- Next new research/exploration task (not load-bearing) launched via `sigil session launch ...` instead of `agent-deck launch`
- Exercised every daily CLI surface: `list --json`, `send`, `output -q`, `show --json`, `status --json`
- Friction log written to `docs/migration-friction.md`; surfaced gaps fed directly into Phase B PRs
- **Outcome:** end-to-end Vigil-on-Sigil smoke test confirmed; the same smoke pass also flagged the stale README claims that drove the v0.2.0 release cut

### Phase B — Fix top 3 friction items (autonomous, small PRs) — **DONE 2026-05-01**
All four friction items shipped:
- Group + parent-session CLI management — `session set-group` / `session set-parent` + `parent_title` in `session show --json` (PR #61)
- `session send --wait --timeout` / `--no-wait` semantics parity (PRs #62, #63)
- `session launch --worktree BRANCH [-b]` compound flow (PR #60)
- TmuxRuntime input-delivery reliability + `--json` stdout cleanliness — error-shape clarity carriers (PRs #59, #64)

**Outcome:** can run a full dogfood task without touching agent-deck. Closes the daily-driver-blocker class for Vigil migration.

### Phase C — Bring `sigil bridge telegram` back up (autonomous) — **gated on 1 human step**

**Not a re-verification — already proven.** `sigil bridge telegram` round-trip was validated in a previous session (see `state.json` → `tools.sigil: "Telegram loop proven"`). The bridge was booted out 2026-04-18 alongside agent-deck's `bridge.py` during the pre-migration freeze, not because it was broken.

- Create launchd plist for `sigil bridge telegram` (same pattern as #5 heartbeat plists at `~/.agent-deck/conductor/launchd/`)
- Use keychain-stored token (`security find-generic-password -s sigil-telegram-token -a "$USER"` — matches what `scripts/install-service.sh` reads at launch)
- Route messages to conductor-ops session (parent linkage working after PR #61)
- Smoke-test one real back-and-forth, then leave the plist running
- **Code is ready — the only remaining gate is a 1-step human action: rotate the Telegram bot token (the previous value circulated in cleartext error logs prior to PR #65) and seat the new value in the keychain entry above.**
- **Done when:** launchd plist installed, one real Telegram ↔ Vigil round-trip confirmed, stays up for 24h without restart

### Phase D — Migrate Vigil itself (higher-stakes, coordinated)
- Tear down current `conductor-ops` agent-deck session. Launch Vigil as a Claude session under `sigil session launch` + `sigil conductor` loop
- Update `~/.agent-deck/conductor/ops/CLAUDE.md` + `OPS.md` to reference `sigil` commands instead of `agent-deck`
- Heartbeat cron migrates from `CronCreate` (session-only) to launchd + `sigil session send conductor-ops "<prompt>"` (ties into cron→launchd migration)
- Keep agent-deck alive in parallel ~48h as fallback
- **Done when:** Vigil running under Sigil exclusively 48h, zero rollback events

### Phase E — Retire agent-deck
- Archive `~/.agent-deck/` (except `bridge.py` source) to `~/.agent-deck-archive/`
- Uninstall agent-deck binary
- Update all conductor `CLAUDE.md` files + `OPS.md` to reference only Sigil CLI
- **Done when:** `agent-deck` not in `PATH`, all docs updated, no live references

## Blockers / coordination

- **Cron → launchd migration** is a Phase D prerequisite. Can land before Phase D or during. Separately queued under Infra.
- **Multi-conductor management** — per-channel conductors (`slack-ops`, `telegram-ops`) need parent-child linkage exposed via CLI. Phase B item.
- **Bridge currently disabled** — Phase C re-enables it *via Sigil*. Not a blocker, sequencing note. Agent-deck's `bridge.py` is intentionally dormant (launchctl booted out 2026-04-18, config.toml platform blocks commented out) pending this migration — do not resurrect it.

## Parallelizable with

- Ting v0.4 build (different repo, Sigil-independent)
- FMT-001 cleanup PRs (small)
- OpenMontage `/make-video` skill (orthogonal)

## Risks

**Low:**
- Surface parity is high. Known-unknowns are mostly ergonomics, not architecture.
- 48h parallel-run window gives easy rollback. agent-deck stays installed until Phase E.

**Medium:**
- Bridge re-enablement touches user-facing infra (Sebastian's phone). One identity-resolution bug = missed message, silent failure. Mitigation: send a deliberate first ping from Sigil as the verification step, not a casual "did it work?"
- Heartbeat migration is the quiet load-bearing piece. Cron → launchd is boring plumbing, but if it lands wrong, Vigil goes silent until manually restarted.

**High (none identified).** If something high-risk surfaces during Phase A, it gets written into the friction log and triaged before Phase B proceeds.

## Why now

- **Capability plateau vs security momentum:** last ~6 weeks (PRs #39–#58) were heavy on security/policy/sanitization. Sigil's daily-driver capability is **implemented-but-not-dogfooded**. Dogfooding before more features beats shipping more sanitization on unvalidated runtime.
- **Agent-deck pain is accumulating:** prompt-delivery bug (2026-04-17 sigil-ci-diskspace launch), stale "Stream idle timeout" reads, 7-day cron expiry. Not crises, just friction that compounds.
- **Sebastian's framing:** "testing Sigil" as the next arc. Migration *is* the test.

## First action

Phase A. Next low-stakes task that Vigil would normally launch via `agent-deck launch` → launch via `sigil session launch` instead. Start the friction log. One task, one log file, one friction pass. Then decide if Phase B starts immediately or batches.

Candidate Phase A tasks (all low-stakes, not load-bearing):
- A docs-only sweep (e.g. refresh stale `CLAUDE.md` / `OPS.md` references)
- A LEARNINGS promotion pass (state.json has 3 candidates queued)
- A worktree cleanup batch (5 stale sigil worktrees from merged PRs)

Any of these is safe — small, reversible, exercises the same CLI surface Vigil uses daily.

---

## Appendix — Source material

- `~/.agent-deck/conductor/ops/WORKQUEUE.md` § "PRIMARY: Migrate Vigil to Sigil" (canonical phase definitions)
- `~/.agent-deck/conductor/ops/state.json` § `pre_compaction_2026_04_19_23_30` (consolidated state)
- `docs/FEATURE-AUDIT.md` (2026-04-08 parity audit — still current on code, pre-dates Phase 1 sanitization completion)
- `docs/ARCHITECTURE.md` + `docs/SECURITY-PLAN.md` (2026-04-18, reflect Phase 1 complete)
