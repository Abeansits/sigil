# Sanitization integration-test fixtures

Known-bad payloads used by the end-to-end pipeline test (Phase B of
PR7). Each file combines multiple attack surfaces so a single run proves
the full stack — sanitizer → conductor → report → audit — actually
catches the overlapping signals, not just one rule in isolation.

The expected behavior for every fixture:

1. The cleaned output contains no part of the injection payload the
   attacker tried to smuggle past visual review.
2. The `SanitizeReport` lists the relevant rule IDs as `findings`.
3. The `text_normalize` block records the stripped Unicode characters.
4. The conductor writes an audit-log entry referencing the report's
   fingerprints.

## Files

| File | Content type | Attack surfaces covered |
|------|--------------|------------------------|
| `bad.html` | `html` | Hidden `<div style="display:none">`, zero-width stego, `ignore prior instructions` injection, `<script>` and HTML-comment smuggling, `aria-label`. |
| `bad.md`   | `markdown` | `<!-- SYSTEM: … -->` comment, raw-HTML block, zero-width stego, `you are now` injection. Consumed once PR5's `sanitize_markdown` lands. |
| `bad.json` | `json` | `\uXXXX` escapes decoding to an injection string, base64 blob smuggled as a benign-named field, nested object with homoglyph header. Consumed once PR5's `sanitize_json` lands. |

## Why pre-provision MD/JSON before PR5

The fixture files are static — PR5 does not need to touch them. By
scaffolding them now we make the PR5 → PR7 integration trivial: the
moment `sanitize_markdown` / `sanitize_json` are exposed, the end-to-end
test can flip from "HTML-only" to "all three formats" without another
review round-trip on fixture content. If a fixture turns out to be
miscalibrated (e.g. a rule ID we ship does not fire on a payload we
thought would trigger it), the fix lands in the integration-test PR,
not here.
