# `FMT-001` scoping — reframe as a routing signal

**Date:** April 19, 2026
**Status:** Landed (PR3.6 on `feature/sanitize-html-detect`)
**Companion doc:** `docs/design/content-sanitization.md` §Pre-dispatch content-type reroute

## The problem `FMT-001` was trying to solve

Threat-model item #8 in the Phase 1 design doc: *a server claims
`Content-Type: text/plain` but serves an HTML document with `<script>`
tags.* An agent that honors the declared type and runs the plain-text
sanitizer never strips the tags, so the model sees live markup in its
context. The Phase 1 mitigation was a post-decode pattern rule,
`FMT-001`, that fired at `High` severity when a plain-text body
contained HTML structural markers. It was intentionally a findings-only
rule: the sanitizer doesn't re-route based on content; the caller's
declared type is authoritative.

## Why the Phase 1 design didn't hold

`FMT-001` Path A (`<!DOCTYPE html>` / `<html>` root marker) is
semantically what we actually want — document-root markers don't show
up in prose. Path B (≥ 2 distinct structural openers AND ≥ N close-tag
occurrences) was meant to catch body-only HTML fragments that lack a
root marker. Two things broke simultaneously at calibration time:

1. **Path B's FP rate on legitimate security prose is unbounded.** The
   PortSwigger XSS cheat sheet (`a06_portswigger_xss_cheatsheet.txt`)
   contains 5 distinct execution-bearing openers (`<svg>`, `<template>`,
   `<form>`, `<style>`, `<script>`) and 62 close-tags as legitimate
   attack-surface enumeration. Any close-tag floor below 62 trips
   Path B on it. Opener-set tightening does not help — every opener
   in the regex appears in the cheat sheet's prose.
2. **"Zero FMT-001 hits on benign" is a hard gate the Path B design
   cannot satisfy.** So the pipeline shipped with `FMT_HTML_CLOSE_TAG_THRESHOLD`
   pinned at 100 as a reluctant workaround (see CALIBRATION.md round-3
   notes). That made Path B useless for fragments that sit between
   "one opener + a dozen close-tags" and "100+ close-tags" — exactly
   the regime real attackers would write in.

## Option space

| Option | Description | Tradeoff |
|--------|-------------|----------|
| **1.** Keep `FMT-001` High + raise Path B thresholds. | Ship the status-quo. | Path B becomes a dead rule; we're still relying on an all-or-nothing heuristic that can't separate "prose discussing HTML" from "HTML being served as plain text". |
| **2.** Delete `FMT-001` entirely. | Rely on downstream defenses. | **Security regression.** Today a server that lies about `text/plain` and serves `<script>` has no defense in the sanitizer at all. |
| **3.** Reframe `FMT-001` as a routing signal. | Use Path A (document-root markers) to *reroute* a declared-PlainText body into the HTML sanitizer before dispatch. Demote the pattern-scan emission to `Info`. | Adds a small pre-dispatch sniff. Keeps the defense for the lying-server case and actively strips instead of just flagging. Path B remains in the scanner as audit metadata. |

Option 3 is the chosen path.

## Option 3 — design

### Pre-dispatch ASCII sniff

Before `dispatch_sanitize` picks a sanitizer, it runs an ASCII-only
byte-level scan over the first 1024 bytes of the raw payload. If the
declared type is `ContentType::PlainText` AND the window contains
`<!DOCTYPE html` or `<html` (case-insensitive, followed by a
tag-name terminator so `<htmlfoo>` does not match), the dispatcher
reroutes to the HTML sanitizer. The sniff never runs UTF-8 decode
first — a payload whose tail contains non-UTF-8 bytes (an
attacker-controlled encoding bug) would otherwise be hard to route
correctly.

Implementation lives in `crates/sigil-content/src/detect.rs`.

### Why document-root markers only

Path B's FP rate makes it unfit for a routing decision. A wrong
reroute costs the caller a full HTML sanitize of what was otherwise a
plain-text payload — that's acceptable for document-root matches
(prose does not typically lead with `<!DOCTYPE html>`) but not for
fragment heuristics. Path B stays in `patterns::has_strong_html_markers`
as non-routing audit signal at `Info` severity.

### Report shape

`SanitizeReport.routed_from: Option<ContentType>` is `Some(declared)`
when the dispatcher rerouted and `None` otherwise. `content_type`
always reflects the effective path that ran. The wrap header's
`content_type:` field uses the effective value (`text/html` after a
reroute), so downstream guardrails that read the wrap header never see
the lied-about declared type.

### Edge cases

1. **ASCII-only sniff** — Avoids re-running UTF-8 validation on
   potentially-malformed bytes. The sniff byte-compares two short
   fixed prefixes; cost is O(window size).
2. **`ContentType::Log` excluded from reroute** — Terminal captures
   legitimately contain DOCTYPE text as part of the captured output.
   Rerouting would destroy the payload the log was meant to preserve.
3. **Path B fragment detector is non-routing** — Too loose for a
   blunt reroute; stays as `Info`-level audit metadata in the scanner.
4. **Wrap-header `content_type:` updated on reroute** — The HTML
   sanitizer renders `content_type: text/html` so downstream
   consumers see the effective type, not the lied-about declared
   type.
5. **`SanitizationRequirement::Required(ContentType)` asserts on
   effective type** — `sigil-policy::evaluate_result` compares
   `report.content_type` (effective) against the requirement. An
   action that declared `Required(PlainText)` and received a body
   that rerouted to `Html` will therefore deny, which is the correct
   behavior: the action promised plain text and received active
   content.
6. **Fingerprint identity** — `raw_fingerprint` is computed from the
   raw bytes before the path decision. Rerouted payloads have the
   same raw fingerprint they would have had without the reroute, so
   correlation across runs is path-independent.

## LOC budget (landed)

- `crates/sigil-content/src/detect.rs` (new) — ~150 LOC with tests
- `crates/sigil-content/src/lib.rs` — pre-dispatch sniff wiring (~30 LOC)
- `crates/sigil-content/src/patterns.rs` — severity demotion + doc update
- `crates/sigil-content/src/html.rs` — `sanitize_with_routed_from` entry
- `crates/sigil-content/src/plain.rs` — plumb `routed_from` through
  `PostStripInput`
- `crates/sigil-core/src/content.rs` — `SanitizeReport.routed_from` field
- `crates/sigil-content/tests/fixtures.rs` — severity expectation
  update; retire "zero FMT-001 on benign" hard gate
- `crates/sigil-content/src/lib.rs` tests — reroute happy path +
  benign-prose-unchanged + Log-excluded + non-UTF-8 payload + already-
  declared-HTML baseline

## Rule-set version

`RULE_SET_VERSION` bumped from `2` → `3` — the `FMT-001` severity
change is observable on every emitted finding, so a report from an
older catalog needs to be recognizably different.
