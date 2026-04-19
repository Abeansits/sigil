# Calibration Principles — `sigil-content`

This file captures the operating principle behind every threshold,
weight, and severity in the sanitization pipeline. Future tuners (human
or agent) should read it before changing a number.

## The principle: start permissive, dial up

When introducing a new rule, weight, or threshold, **bias toward false
positives**. Set the rule loose enough that it fires on borderline
content. Then watch the FP-rate gate over the benign corpus — if real
operational data shows the FP rate is unsustainable, *raise* the
threshold in a reviewable change. Once a real distribution is in hand,
the right ceiling becomes obvious.

The reverse — start strict, relax after missing true positives —
fails closed in the wrong direction for security content. A missed true
positive is invisible until it bites; a false positive is a noisy log
line that makes the bite obvious.

> "It's better to have false positives and then slowly increase, and
> vice versa. We can always bump it up later if we get a lot of false
> positives." — Sebastian, PR #52 round-3 calibration, 2026-04-17

## What this means for the FP-rate gate

`tests/fp_baseline.json` records the **measured** number of benign
fixtures that score at or above `RISK_GATE_THRESHOLD`. The CI gate
asserts `measured_hits ≤ baseline_hits + 1` — a regression detector,
not a zero-suppressor. A non-zero baseline is normal and expected once
the rule severities are at their real values; the baseline shifting up
during a tuning pass is also expected (commit the new snapshot in the
same change).

The round-3 "Zero High hits on benign" and "Zero FMT-001 hits on
benign" hard gates have been **retired in PR3.6**. The real attacker
shape that drove FMT-001 (a server claiming `text/plain` while serving
`<!DOCTYPE html>`) is now caught earlier by the pre-dispatch reroute
in `dispatch_sanitize` — the ASCII sniff routes those bodies to the
HTML sanitizer for a safer strip and records `routed_from` in the
report. The pattern-scan emission is now `Info`-level audit metadata,
so the benign corpus can legitimately trip `FMT-001` Path B on prose
discussion of HTML without crossing the risk gate. The absolute-delta
baseline check (`measured_hits ≤ baseline_hits + 1`) remains the
regression detector.

The `INJ-*` High promotion still stands: the High tier is earned by
direct attack phrasings, and distinct-rule scoring still keeps benign
content from stacking combined signal past the threshold.

### PR3.6 — FMT-001 reframe as routing signal

The round-3 conflict around `FMT_HTML_CLOSE_TAG_THRESHOLD` (the
PortSwigger XSS cheat sheet tripping Path B on 62 close-tags of
legitimate attack-surface enumeration) was resolved by moving the
actual routing decision out of the pattern scanner entirely. Path A
(document-root `<!DOCTYPE html>` / `<html>`) is now a pre-dispatch
sniff in `detect::looks_like_html_document_root`; Path B stays where
it was but emits at `Info` severity so its false-positive rate on
security prose is no longer a structural problem. See
`docs/design/fmt-001-scoping.md` and
`docs/design/content-sanitization.md §Pre-dispatch content-type reroute`
for the full rationale.

## Severity tiering (current state — PR3.6)

| Tier | Rules | Rationale |
|------|-------|-----------|
| `High` | `INJ-001..007` | Canonical attack phrasings. Real attackers' first move; deserves the strongest score signal even at the cost of benign-corpus noise. |
| `Medium` | `MIX-001`, `ENC-003` | Suspicious shape but not always attack (Unicode TR #39 prose, Markdown image data: URIs). |
| `Low` | `ENC-001/002`, `REP-001/002` | Weak signals that combine into the score but don't push the gate alone. |
| `Info` | `WRP-001`, `FMT-001` | Observability only, score-neutral. `FMT-001` reframed in PR3.6 — the routing-relevant case is handled by the pre-dispatch reroute, so the pattern-scan emission is audit metadata. |

## Score weights (current state — round 3)

| Severity | Weight per distinct rule |
|----------|--------------------------|
| `High` | 50 |
| `Medium` | 20 |
| `Low` | 6 |
| `Info` | 0 |

Plus signal bonuses:
- `+10` if [`NormalizeResult::stripped_count`] > 0
- `+15` if `repetition_ratio >= 0.85`

Capped at 100. Counted by **distinct `rule_id`**, not raw match count
— a single noisy regex cannot blow up the score.

`RISK_GATE_THRESHOLD = 50`. A single High hit reaches the gate
directly; a Medium + a normalize-strip bonus also reaches it; two
distinct Mediums + a bonus reach it.

## When to bump versions

- `RULE_SET_VERSION` — adding, removing, or renaming a `rule_id`. Bumped
  separately from severity changes (severity is observable on the
  finding; the catalog identity isn't).
- `SCORING_VERSION` — changing weights, bonuses, the threshold, or any
  arithmetic in `risk::compute`.

A report from an older catalog or scorer must be recognizably different
from a current one. Audit-log readers consume both versions to interpret
historical findings correctly.

## Lock-step thresholds

`RISK_GATE_THRESHOLD` (in `risk.rs`) and the policy evaluator's
`NeedsApproval` boundary for `AgentRuntime`-initiated fetches must move
together. Drift between them is a bug.
