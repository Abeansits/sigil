# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-01

Theme: harden the ingest edge, close daily-driver gaps in the CLI surface, and unify policy routing.

### Added

- `sigil-content` Phase 1 external-content sanitization pipeline — runs on bytes fetched from the web, attached to a bridge message, or returned by an MCP tool *before* they reach an agent's context. Format-aware strip for plain text, HTML, Markdown, and JSON; text-layer normalize via `sigil-policy::normalize`; injection-pattern scan with FP-rate gate; nonce-delimited provenance wrap; keyed-HMAC fingerprint report. Wired through the conductor via `ActionService::dispatch_fetch_external_content`, with `SanitizationRequirement` enforced by the policy engine on post-dispatch results, and a `sigil content sanitize` CLI debug harness ([#43], [#45], [#50], plus PR3 / PR4 / PR5 direct pushes, [#55], [#56], [#57], [#58]).
- `ActionService` unified policy pipeline — worktree, identity, status, and bridge T0 reads now route through one policy entrypoint, with grant-store wiring and post-dispatch `evaluate_result` ([#37], [#41]).
- `sigil-memory` operational memory crate — episode writer, reader, mechanical consolidator, idle consolidation hooks, integration tests, and CLI subcommands ([#27], [#28], [#29], [#30], [#35], [#38]); design doc ([#25]); memory config parsed from the `[memory]` section of `.sigil/config.toml` ([#29]).
- Identity reload subsystem — `IdentitySpec`, `LifecycleEvent`, `LifecycleHooks` trait ([#18]), `identity_json` column on the sessions table ([#20]), `LifecycleHooks` implementation for `TmuxRuntime` ([#21]), project config parser + `--identity` CLI flag ([#22]), `identity reload` / `identity snapshot` CLI commands plus integration test ([#23]).
- OpenCode as a supported tool kind across `sigil-core`, `sigil-runtime`, and `sigil-cli` ([#66]).
- `session set-group` and `session set-parent` CLI commands; `parent_title` rendered in `session show --json` ([#61]).
- `session launch --worktree BRANCH [-b]` compound flow — one call creates session + worktree + branch ([#60]).
- `session send --timeout <secs>` and `session send --no-wait` for parity with the agent-deck shape ([#62]).
- `sigil run` for inline command execution against a session, plus the bridge → conductor response path ([#31]); bridge response path completion ([#32]); `[bridge]` config section + conductor command tests ([#34]); configurable bridge identity via env vars (PR series merged via [#34]).
- launchd service for persistent Telegram bridge (`scripts/install-service.sh` + plist + Keychain-backed token loader) ([#33]).
- CLI black-box tests (Tier 3) ([#24]); ActionService grant-store wiring + non-allow audit coverage ([#46]).
- Codex / style-guide agent docs ([#26]); content-sanitization pipeline design doc ([#39]); benign-corpus candidates + Rust 1.95 clippy hygiene ([#50]); identity-reload design + implementation plan ([#17]); ASCII banner + "The Name" section in README ([#19]); agent memory systems research note.

### Changed

- Session title uniqueness is now enforced; stale docs that contradicted it were updated ([#36]).
- OpenHands PR review workflow added (label-gated) and tightened for inline + structured output ([#42], plus a follow-up CI hardening commit).
- CI runner now frees disk space before the Rust build to prevent OOD-disk failures ([#51]).

### Fixed

- TmuxRuntime now auto-launches the tool and reliably submits input — closes a class of "prompt stuck in textbox" failures ([#59]).
- Session-restart race in tmux teardown closed ([#48]).
- `--json` CLI output kept pure: tracing logs route to stderr instead of polluting stdout ([#64]).
- `session send --timeout` is now rejected without `--wait` (Codex P2 follow-up; one-line guard, [#63]).
- Bridge integration tests use the real Telegram ID and the resolved identity env var (two follow-up commits to the bridge identity work).

### Security

- Audit HMAC key now resolves in priority order `SIGIL_AUDIT_KEY` env > macOS Keychain entry under service `sigil` / account `audit-hmac` > opt-in dev fallback ([#40]); key bytes are zeroized on drop and audit errors carry typed sources ([#47]).
- Telegram bot token redacted from `reqwest` error logs to prevent token leakage on transport failures ([#65]).
- `cargo-deny` added for supply-chain security auditing ([#16]).
- All of the new ingest-edge sanitization (see *Added*) is security-relevant: nonce wrap, injection-pattern scan, and the `SanitizationRequirement` policy gate harden the path from external content into agent context.

### Potentially Breaking

Pre-1.0, but downstream consumers should know:

- Session title uniqueness is now enforced at the store layer ([#36]). Calls that previously created duplicate titles will now fail; reuse a title only after removing the prior session, or rename it via `session set-group` / `set-parent` workflows.
- `ActionService` routing ([#41]) shifts the error and authorization surface for worktree, identity, status, and bridge T0 reads — observable shapes can change for callers that depended on the pre-`ActionService` error variants.
- `TmuxRuntime` now auto-launches the tool and submits input only after the tool is ready ([#59]). Callers that previously raced "send before tool ready" will see different timing; the surfaced behavior is more reliable but not bit-identical.
- `sigil session send --timeout <secs>` is now rejected when `--wait` is absent ([#63]). Scripts that combined `--timeout` with `--no-wait` (or with neither flag) must add `--wait` or drop `--timeout`.

### Notes

- 11-crate workspace (added `sigil-content`); workspace structure described in `docs/ARCHITECTURE.md`.
- `docs/FEATURE-AUDIT.md`, `docs/PRODUCTION-READINESS.md`, and `README.md` refreshed to match shipped reality. Phase A and Phase B of the Vigil → Sigil migration are marked DONE in `docs/PRODUCTION-READINESS.md` (2026-05-01); Phase C is gated on a one-step Telegram-token rotation.
- Verified 2026-05-01: `cargo test --workspace` (991 passed, 0 failed, 0 ignored), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check --all`, `./target/release/sigil --version` reports `sigil 0.2.0`.

[#16]: https://github.com/Abeansits/sigil/pull/16
[#17]: https://github.com/Abeansits/sigil/pull/17
[#18]: https://github.com/Abeansits/sigil/pull/18
[#19]: https://github.com/Abeansits/sigil/pull/19
[#20]: https://github.com/Abeansits/sigil/pull/20
[#21]: https://github.com/Abeansits/sigil/pull/21
[#22]: https://github.com/Abeansits/sigil/pull/22
[#23]: https://github.com/Abeansits/sigil/pull/23
[#24]: https://github.com/Abeansits/sigil/pull/24
[#25]: https://github.com/Abeansits/sigil/pull/25
[#26]: https://github.com/Abeansits/sigil/pull/26
[#27]: https://github.com/Abeansits/sigil/pull/27
[#28]: https://github.com/Abeansits/sigil/pull/28
[#29]: https://github.com/Abeansits/sigil/pull/29
[#30]: https://github.com/Abeansits/sigil/pull/30
[#31]: https://github.com/Abeansits/sigil/pull/31
[#32]: https://github.com/Abeansits/sigil/pull/32
[#33]: https://github.com/Abeansits/sigil/pull/33
[#34]: https://github.com/Abeansits/sigil/pull/34
[#35]: https://github.com/Abeansits/sigil/pull/35
[#36]: https://github.com/Abeansits/sigil/pull/36
[#37]: https://github.com/Abeansits/sigil/pull/37
[#38]: https://github.com/Abeansits/sigil/pull/38
[#39]: https://github.com/Abeansits/sigil/pull/39
[#40]: https://github.com/Abeansits/sigil/pull/40
[#41]: https://github.com/Abeansits/sigil/pull/41
[#42]: https://github.com/Abeansits/sigil/pull/42
[#43]: https://github.com/Abeansits/sigil/pull/43
[#45]: https://github.com/Abeansits/sigil/pull/45
[#46]: https://github.com/Abeansits/sigil/pull/46
[#47]: https://github.com/Abeansits/sigil/pull/47
[#48]: https://github.com/Abeansits/sigil/pull/48
[#50]: https://github.com/Abeansits/sigil/pull/50
[#51]: https://github.com/Abeansits/sigil/pull/51
[#55]: https://github.com/Abeansits/sigil/pull/55
[#56]: https://github.com/Abeansits/sigil/pull/56
[#57]: https://github.com/Abeansits/sigil/pull/57
[#58]: https://github.com/Abeansits/sigil/pull/58
[#59]: https://github.com/Abeansits/sigil/pull/59
[#60]: https://github.com/Abeansits/sigil/pull/60
[#61]: https://github.com/Abeansits/sigil/pull/61
[#62]: https://github.com/Abeansits/sigil/pull/62
[#63]: https://github.com/Abeansits/sigil/pull/63
[#64]: https://github.com/Abeansits/sigil/pull/64
[#65]: https://github.com/Abeansits/sigil/pull/65
[#66]: https://github.com/Abeansits/sigil/pull/66

## [0.1.0]

Initial public release.
