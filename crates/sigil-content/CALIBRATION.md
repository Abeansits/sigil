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

Two **hard gates** sit on top of the absolute-delta check:

1. Zero `Severity::High` hits on the benign corpus — anti-gaming, keeps
   the High tier semantically meaningful. *Note: the round-3 `INJ-*`
   bump to High intentionally raises the per-fixture score, but the
   distinct-rule scoring still relies on combined signal to push
   benign content past the threshold.*
2. Zero `FMT-001` hits on the benign corpus — a server lying about
   `Content-Type` is never benign signal; the rule must fire only on
   structural HTML, not on prose discussion of HTML.

If a tuning change causes either hard gate to break, **flag it** in a
PR comment instead of silently retuning the rule to keep the gate
green. The hard gates encode invariants; if the rule is structurally
incompatible with the invariant, the rule needs more thought, not the
test.

### Open calibration question (PR #52, round 3)

Sebastian's request to drop `FMT_HTML_CLOSE_TAG_THRESHOLD` from 100 to
20 was held back. Empirically the PortSwigger XSS cheat-sheet fixture
contains 5 distinct execution-bearing opener tags (svg, template,
form, style, script) plus 62 close-tags as legitimate attack-surface
enumeration; any close-tag floor below 62 trips path-B, which violates
the "FMT-001 zero on benign" hard gate. The structural conflict needs
one of:

1. Accept FMT-001 hits on benign (relax the hard gate).
2. Exclude HTML-prose fixtures from the FP corpus (carve out a06 and
   similar XSS cheat sheets as out-of-scope for the plain-text gate).
3. Bring path-B opener semantics into stricter alignment with the
   threat model — e.g. require an opener whose *content* is also
   execution-bearing, not just discussion-of-HTML prose.

Pending Sebastian's call.

## Severity tiering (current state — round 3)

| Tier | Rules | Rationale |
|------|-------|-----------|
| `High` | `INJ-001..007`, `FMT-001` | Canonical attack phrasings + content-type lying. Real attackers' first move; deserves the strongest score signal even at the cost of benign-corpus noise. |
| `Medium` | `MIX-001`, `ENC-003` | Suspicious shape but not always attack (Unicode TR #39 prose, Markdown image data: URIs). |
| `Low` | `ENC-001/002`, `REP-001/002` | Weak signals that combine into the score but don't push the gate alone. |
| `Info` | `WRP-001` | Observability only, score-neutral. |

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
