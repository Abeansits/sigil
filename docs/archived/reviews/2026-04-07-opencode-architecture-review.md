# Architecture Review — sigil

> ⚠️ **Archived 2026-05-02. Historical snapshot, stale status claims.**
> This review was written 2026-04-07 against an 8-crate workspace.
> Since then the workspace has grown to 11 crates, the container
> backend, the host-side MCP server, the Phase 1 content sanitization
> pipeline, the Keychain-backed audit key, and the `ActionService`
> unified policy pipeline have all shipped. Several "Critical" /
> "Moderate" gaps in this review (`GrantStore` not wired, conductor
> hardcoded to `TmuxRuntime`, `strip_ansi` regex fallback, prefix-match
> grants) have been addressed in PRs #36–#46. The architectural
> critique itself is preserved as historical context. For the current
> system, read [`docs/ARCHITECTURE.md`](../../ARCHITECTURE.md).

> Experimental review snapshot. Helpful for discussion, but not a source-of-truth replacement for `CLAUDE.md`, `README.md`, or `docs/ARCHITECTURE.md`.

**Date:** 2026-04-07
**Reviewer:** opencode
**Scope:** Full workspace review — all 8 crates, proposal docs, and code conventions

> Exact crate-size and test-count metrics are intentionally maintained in `README.md` and `docs/ARCHITECTURE.md`, not in this experimental review note.

---

## Executive Summary

The architecture is well-designed and security-first. The crate boundaries are clean, the Action enum is a solid authority primitive, and the code follows project conventions meticulously. The implementation is substantial — not scaffolding — with real logic, tests, and working integrations across all crates.

The main gaps are: GrantStore not wired into the evaluator, the Conductor hardcoded to TmuxRuntime (defeating the trait abstraction), and the container backend not yet implemented (expected per build order).

---

## What's Actually Built

| Crate | Status | Notes |
|-------|--------|-------|
| `sigil-core` | Fully implemented | Action enum, origins, principals, trust model, traits, protocol messages |
| `sigil-policy` | Substantially implemented | Zone transitions, tier eval, input normalization, path validation, fatigue guard |
| `sigil-audit` | Fully implemented | HMAC-chained JSONL writer and chain verification |
| `sigil-store` | Fully implemented | SQLite with migrations, session CRUD, grant persistence, cleanup |
| `sigil-runtime` | Implemented (tmux only) | `TmuxRuntime`, Claude Code adapter, worktree manager |
| `sigil-bridge` | Implemented (types + loops) | Telegram long-polling, Slack Socket Mode, identity resolution, rate limiting |
| `sigil-conductor` | Implemented | Heartbeat loop, reconciliation, bridge message handling |
| `sigil-cli` | Implemented | Clap commands, audit wiring, and cross-crate integration tests |

For maintained workspace metrics, use [`README.md`](/Users/zebas/Developer/sigil/README.md) and [`docs/ARCHITECTURE.md`](/Users/zebas/Developer/sigil/docs/ARCHITECTURE.md).

---

## Strengths

### 1. Clean Dependency DAG

The crate dependency graph is a proper DAG with no cycles:

```
sigil-core → (no internal deps)
sigil-audit → sigil-core
sigil-policy → sigil-audit, sigil-core
sigil-store → sigil-core, sigil-policy
sigil-runtime → sigil-policy, sigil-core
sigil-bridge → sigil-policy, sigil-audit, sigil-core
sigil-conductor → sigil-runtime, sigil-store, sigil-policy, sigil-audit, sigil-core
sigil-cli → sigil-conductor, sigil-runtime, sigil-store, sigil-audit, sigil-core
```

Bridge and conductor never depend on each other. Both use traits defined in `sigil-core` (`MessageSink`, `MessageSource`, `ActionRouter`).

**Note:** `sigil-runtime` and `sigil-bridge` do NOT depend on `sigil-store` — they only need the policy layer and core types. Storage is wired in at the `sigil-conductor` and `sigil-cli` levels.

### 2. Action Enum as Sole Authority

No string commands cross module boundaries. Every operation is a typed `Action` variant with an `ActionOrigin`. Key design decisions:

- **No `Shell(String)` variant.** `ExecuteHostCommand` uses `CommandTemplate` — named, validated commands only.
- **`BreakGlass` is the only escape hatch** and requires explicit justification.
- **`HumanApproved` wraps the original origin** in `Box<ActionOrigin>` to preserve the full provenance chain.
- **`#[non_exhaustive]`** on the enum allows future variants without breaking changes.

### 3. Authority vs Observation Split

This is the single most important architectural rule, and it's enforced:

```
AUTHORITY PATH:  Agent → MCP tool → ActionRequest → sigil-policy → execute
OBSERVATION PATH: Terminal output → ToolAdapter::parse_output() → AgentSignal (status only)
```

`ToolAdapter::parse_output()` produces `AgentSignal` (running/waiting/error states), never `ActionRequest`. If a future MCP approval transport is added, it should remain a thin policy-mediated proxy rather than direct host authority.

### 4. HMAC-Chained Audit Trail

Well-implemented in `sigil-audit`. Each entry carries:

1. SHA-256 content hash of the event payload
2. `prev_hash` linking to the prior entry's HMAC
3. HMAC-SHA256 tag computed over `content_hash || prev_hash`

Chain verification checks all three invariants. Recovery from existing files reads the last line to reconstruct the chain tail. Genesis hash for fresh files.

### 5. Input Normalization

`sigil-policy::normalize` covers:

- Zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
- Tag characters (U+E0001–U+E007F)
- Directional overrides (U+202A–U+202E, U+2066–U+2069)
- Variation selectors (U+FE00–U+FE0F)
- Control characters (except \n, \t)
- ANSI escape sequences (CSI, OSC, charset selection)
- Homoglyph detection (flags mixed-script words, doesn't block)

Normalization happens at two points: bridge ingress and session output read.

### 6. Path Traversal Prevention

Two-layer defense:

1. `quick_path_check` — rejects null bytes and control characters without filesystem access
2. `validate_path` — canonicalizes path, checks against allowed roots, handles non-existent files via parent canonicalization

### 7. Approval Fatigue Mitigation

`FatigueGuard` uses a sliding-window rate limiter with three levels (Normal, Warning, HighRisk) and mandatory cooldown enforcement. Prevents "auto-approve" cognitive vulnerability.

### 8. Code Quality & Conventions

The code follows CLAUDE.md meticulously:

- `#![forbid(unsafe_code)]` enforced via workspace lints
- No `.unwrap()` in production code — `.expect()` with justification only
- `thiserror` in library crates, `anyhow` in application crates
- `#[non_exhaustive]` on all public enums
- Newtype pattern for domain IDs (`SessionId(Ulid)`, not bare `Ulid`)
- Explicit match arms — no wildcard `_ =>` on enums
- Import order: std → external → workspace crates
- Functions < 50 lines, < 7 parameters
- `impl Future` return syntax on traits (no `async-trait` dependency)

### 9. Integration Test Coverage

The `sigil-cli/tests/` directory contains cross-crate integration tests:

- `audit_chain.rs` — HMAC chain integrity, tamper detection, recovery after restart
- `audit_integration.rs` — full write-verify cycle
- `policy_flow.rs` — end-to-end policy evaluation across CLI, Slack, and agent origin scenarios
- `session_lifecycle.rs` — create, state changes, deletion
- `path_validation.rs` — traversal prevention across edge cases
- `bridge_normalization.rs` — input sanitization through the bridge path

These tests exercise real cross-crate flows: `sigil-core → sigil-policy`, `sigil-policy → sigil-audit`, `sigil-store` persistence, etc.

---

## Gaps & Concerns

### Critical

#### 1. GrantStore Not Wired Into Evaluator

**Files:** `crates/sigil-policy/src/evaluator.rs:108-113`, `137-142`

The `GrantStore` trait is fully defined and tested. `sigil-store` implements it. But the evaluator has hardcoded TODO comments where grant lookups should happen:

```rust
fn check_privileged_approval(request: &ActionRequest, capability: Capability) -> PolicyDecision {
    if is_human_approved(&request.origin) {
        return PolicyDecision::Allow;
    }
    // TODO: check grant store
    PolicyDecision::NeedsApproval {
        description: format!("{capability:?} requires human approval (tier 3+)"),
    }
}
```

This means T2 and T3+ actions from non-human origins **always require approval** even if a valid grant exists. The entire approval grant system is non-functional until this is wired.

#### 2. Conductor Hardcoded to TmuxRuntime

**File:** `crates/sigil-conductor/src/lib.rs:36-40`

```rust
pub struct Conductor {
    store: Arc<Store>,
    runtime: Arc<TmuxRuntime>,  // ← concrete type, not trait
    heartbeat_interval: Duration,
}
```

The `Conductor` takes `Arc<TmuxRuntime>` instead of `Arc<dyn SessionRuntime>`. This makes it impossible to swap in a container runtime without changing the conductor signature. The whole point of the `SessionRuntime` trait is lost here.

### Moderate

#### 3. `EvaluatorConfig` Is Empty

**File:** `crates/sigil-policy/src/evaluator.rs:19-22`

No per-user tier ceilings, no capability overrides. All policy is hardcoded in `resolve_principal()` in `sigil-core`. The `EvaluatorConfig` struct is a placeholder.

#### 4. `strip_ansi` Regex Fallback Silently Degrades Security

**File:** `crates/sigil-policy/src/normalize.rs:44-47`

```rust
.unwrap_or_else(|_| {
    Regex::new("").expect("empty regex is infallible")
})
```

If the main regex fails, it falls back to an empty regex that matches nothing — meaning ANSI codes pass through silently. For a security function, a panic would be more appropriate since this is a programming error we want to catch immediately.

#### 5. `ApprovalGrant::matches` Uses Prefix Matching

**File:** `crates/sigil-policy/src/grants.rs`

Resource scope uses `starts_with` for matching. `/home/paul` would match `/home/paulie/secret`. Tests use trailing slashes as mitigation, but the API doesn't enforce it. A proper path prefix check (ensuring boundary at `/` or exact match) would be safer.

#### 6. `BridgeMessage` Lacks an ID

**File:** `crates/sigil-core/src/protocol.rs`

Unlike `ActionRequest` which has `RequestId`, `BridgeMessage` has no unique identifier. This makes audit trail correlation harder if a single bridge message spawns multiple actions.

#### 7. Conductor Command Parsing Is String-Based

**File:** `crates/sigil-conductor/src/lib.rs:167-246`

`handle_command` does `text.splitn(3, ' ')` and matches on strings. This breaks the "no string commands" principle, though it's limited to the bridge interface (not the internal authority path). Still, it's a code smell in a system that otherwise uses typed enums exclusively.

### Minor

#### 8. No Container Backend Yet

`sigil-runtime` only has tmux. The container feature gate is planned but not implemented. Expected per the build order, but the security story is incomplete without Apple Containers.

#### 9. `FatigueGuard` Uses `OffsetDateTime::now_utc()` Directly

**File:** `crates/sigil-policy/src/fatigue.rs`

Makes it hard to test time-dependent behavior without `#[tokio::test(start_paused = true)]`. The public API doesn't support time injection.

---

## Suggestions

### Suggestion [Refactor] ✨ — Conductor Should Use Trait Objects

Change `Conductor` to accept `Arc<dyn SessionRuntime>` instead of `Arc<TmuxRuntime>`. This would:

- Enable container runtime swapping without conductor changes
- Make testing easier (inject a fake runtime)
- Actually use the trait abstraction you've already defined

```rust
pub struct Conductor {
    store: Arc<Store>,
    runtime: Arc<dyn SessionRuntime>,
    heartbeat_interval: Duration,
}
```

### Suggestion [Improvement] ✨ — Add `Action::required_tier()` Convenience Method

Currently you call `action.required_capability().minimum_tier()` everywhere. A direct method would improve ergonomics:

```rust
impl Action {
    pub fn required_tier(&self) -> Tier {
        self.required_capability().minimum_tier()
    }
}
```

### Suggestion [Improvement] ✨ — Wire GrantStore Into Evaluator

The infrastructure is all there — the trait, the SQLite implementation, the grant model. The evaluator needs to:

1. Accept a `GrantStore` reference in its config
2. Call `store.find_grant()` before returning `NeedsApproval`
3. Check `grant.is_valid()` and `grant.matches()` before allowing

### Suggestion [Cleanup] ✨ — Panic on `strip_ansi` Regex Failure

Replace the empty regex fallback with a panic. If regex compilation fails, that's a programming error:

```rust
let fallback = Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").expect("ANSI strip regex must compile");
```

Or better, use `LazyLock` so it's compiled once at startup and panics immediately if broken.

### Suggestion [Improvement] ✨ — Add `BridgeMessage::id` Field

Give bridge messages a unique `RequestId` for audit trail correlation:

```rust
pub struct BridgeMessage {
    pub id: RequestId,
    pub origin: ActionOrigin,
    pub text: String,
    pub target_session: Option<SessionId>,
    pub is_command: bool,
}
```

### Suggestion [Cleanup] ✨ — Fix Resource Scope Matching

Replace `starts_with` with a proper path boundary check:

```rust
fn matches_resource_scope(scope: &str, resource: &str) -> bool {
    if scope == resource {
        return true;
    }
    // Exact path prefix with boundary (e.g., "/home/paul/" matches "/home/paul/secret")
    resource.starts_with(scope) && (scope.ends_with('/') || resource[scope.len()..].starts_with('/'))
}
```

---

## Security Assessment

| Layer | Status | Notes |
|-------|--------|-------|
| Input sanitization | ✅ Implemented | Bridge ingress + session output, 5 char categories + ANSI |
| Permission tiers | ✅ Implemented | Action enum + tier ceiling per principal |
| Sandboxed execution | ❌ Not implemented | runtime is tmux-only today; container backend remains future work |
| Audit trail | ✅ Implemented | HMAC-chained JSONL with chain verification |
| Approval gates + TTL | ⚠️ Partial | Model exists, but GrantStore not wired into evaluator |
| Network read/write split | 📋 Planned | Documented in proposal, not yet implemented |
| Rate limiting + allowlist | ✅ Implemented | `RateLimiter` in sigil-bridge, identity resolution |
| Supply chain hardening | ✅ Implemented | Rust-only deps, no npm/pip, pinned Cargo.lock |

**Accepted risks (documented and acknowledged):**

1. tmux-backed sessions execute on the host because no sandbox backend exists yet
2. Git hook injection via `git push` — mitigated by branch protection rules
3. Approval fatigue — `FatigueGuard` exists, but it is not wired into approval handling yet
4. Stored approval grants exist, but evaluator-side enforcement is still missing
5. Fetched-content injection remains outside the current sanitization pipeline

---

## Verdict

This is a well-architected system with a clear security model, clean crate boundaries, and solid implementation progress. The code quality is high — conventions are followed, tests are comprehensive, and the design decisions are well-documented.

### Build Order Progress

The original proposal build-order checklist has been overtaken by the current workspace. For maintained landed-vs-backlog tracking, see [`docs/archived/REWRITE-PROPOSAL.md`](../REWRITE-PROPOSAL.md) instead of this review note.

### Architectural Philosophy

This is **defense-first by design**. The constraints are tight:

- No `Shell(String)` — only named `CommandTemplate`s
- `BreakGlass` requires explicit justification and local-only origin
- Terminal parsing cannot produce `ActionRequest`s — ever
- MCP servers are policy-mediated proxies, not host shells
- Input normalization happens at ingress AND at session output read

The adversary model is sophisticated: prompt injection via fetched content, Unicode steganography, homoglyph attacks, path traversal, approval fatigue. Countermeasures are layered.

### Priority fixes before production:

1. Wire `GrantStore` into the evaluator (critical — approval system is non-functional without it)
2. Change `Conductor` to use `dyn SessionRuntime` (critical — defeats trait purpose)
3. Fix `strip_ansi` fallback (moderate — silent security degradation)
4. Add `BridgeMessage` IDs (moderate — audit correlation)

### Additional Suggestions

**[Refactor]** — `resolve_principal()` in `sigil-core/src/principal.rs` hardcodes defaults (the local CLI principal at T3Plus). This should live in config/sigil-store so it's actually configurable per-deployment.

**[Architecture]** — Consider making the Conductor's bridge command handling go through `ActionRequest` too. The `/status`, `/sessions`, `/send` commands currently use string parsing. If these were regular Actions, the authority path would be unified and auditable.
