# Steganography Defense Analysis

**Source:** ST3GG toolkit (Pliny/elder-plinius) — 112 techniques, ALLSIGHT detection engine
**Context:** Maps ST3GG's attack surface against sigil defenses. Companion to [`AGENT-TRAPS-DEFENSE.md`](/Users/zebas/Developer/sigil/docs/AGENT-TRAPS-DEFENSE.md).
**Status note (2026-05-02):** This file describes the full hardening pipeline. The workspace implements text normalization, tmux-output ANSI stripping, Phase 1 web sanitization (HTML/Markdown/JSON/plain in `sigil-content`, fired by the conductor's `dispatch_fetch_external_content` and the MCP `fetch_url` tool when constructed with a sanitizer + fetcher; default fetcher is `DisabledFetcher`), and host-side sandbox network controls (`DomainProxy` for Apple Containers in `Filtered` mode, behind the `container` feature). Media (image/audio/PDF) sanitization is the remaining Phase 2 work. Status flags below use the convention: ✅ Implemented • ✅ Implemented (conditional) — gated on container filtered mode or sanitizer-configured server • ⚠️ Partial • ❌ Not defended at our layer.

---

## ST3GG Coverage: 112 Techniques Across 6 Categories

### Text/Unicode — PRIMARY THREAT (bridge messages, session output)

| Technique | Our defense (strip-invisible) | Gap? |
|-----------|------------------------------|------|
| Zero-width chars (ZWSP, ZWNJ, ZWJ) | ✅ Covered | — |
| Invisible ink tags | ✅ Covered | — |
| Homoglyph substitution | ✅ Covered (mixed-script detection) | — |
| Variation selectors | ✅ Covered | — |
| Combining diacritics | ⚠️ Not confirmed | Check coverage |
| Confusable whitespace | ✅ Covered (whitespace patterns) | — |
| Emoji substitution | ❌ Not covered | New technique — encode data in emoji choices |
| Capitalization encoding | ❌ Not covered | Encode bits in upper/lower case patterns |

**Action:** Verify strip-invisible against combining diacritics. Evaluate whether emoji substitution and capitalization encoding are realistic threats for our use case (likely low risk — these are subtle and low-bandwidth).

### Image — RELEVANT (downstream tools that fetch images, social media research)

| Technique | Defense | Status |
|-----------|---------|--------|
| LSB embedding (PNG, BMP, TIFF, etc.) | JPEG re-encode (quality 85) destroys LSB | ✅ |
| Alpha channel LSB | JPEG re-encode strips alpha entirely | ✅ |
| PNG filter-type encoding | JPEG re-encode converts format | ✅ |
| Palette manipulation | JPEG re-encode converts to non-paletted | ✅ |
| DCT frequency domain | JPEG re-encode at different quality disrupts DCT coefficients | ⚠️ Partially — high-quality re-encode may preserve some DCT stego |
| F5 JPEG | JPEG re-encode disrupts F5 embedding | ⚠️ Partially — F5 is designed for some robustness |
| PNG+ZIP polyglots | JPEG re-encode eliminates polyglot structure | ✅ |
| EXIF/XMP/tEXt metadata | Metadata stripping removes all | ✅ |

**Primary defense:** Re-encode all external images as JPEG quality 85 + strip all metadata. This destroys the vast majority of image stego.

**For robustness against DCT/F5:** Resize image slightly (99%) before re-encode. The geometric transform + resampling breaks frequency-domain alignment.

**Detection (forensic, not blocking):** ALLSIGHT's chi-square analysis and bit-plane entropy could detect stego in original images before re-encoding. Log findings to audit trail.

### Document/Web — RELEVANT (agents fetch and parse HTML, JSON, Markdown)

| Technique | Defense | Status |
|-----------|---------|--------|
| HTML comments | Stripped in `sigil-content` HTML pipeline | ✅ Implemented (conditional on sanitizer-configured server) |
| HTML hidden elements (`display:none`, `visibility:hidden\|collapse`, `opacity:0`, `hidden`/`aria-hidden`) | Stripped in `sigil-content` HTML pipeline (positional off-screen CSS not detected) | ✅ Implemented (conditional) for the listed property/attribute set |
| HTML `aria-label` injection | `aria-label` attribute stripped (along with `title` and non-image `alt`); generic `aria-*` is not enumerated | ✅ Implemented (conditional, scoped to `aria-label`) |
| JSON Unicode escapes | Text-layer Unicode normalize runs after JSON decode (zero-width, tag chars, directional overrides, variation selectors, control chars) | ✅ Implemented (conditional) |
| Markdown comments | Stripped in `sigil-content` Markdown pipeline | ✅ Implemented (conditional on sanitizer-configured server) |
| XML CDATA/processing instructions | Strip if processing XML | ⚠️ Low priority |
| CSV/YAML/TOML/INI comment encoding | Low risk — agents rarely parse raw config from untrusted sources | ✅ Low priority |
| PDF streams/XMP | Low current priority — PDF processing is rare in this workspace | ✅ Low priority |

**Action:** Add to WebFetch output sanitizer: strip HTML comments, hidden elements, aria-labels, and Markdown comments. Normalize JSON Unicode escapes.

### Audio — LOWER PRIORITY (trusted TTS provider, e.g. ElevenLabs)

| Technique | Defense | Status |
|-----------|---------|--------|
| Sample LSB (WAV, AIFF, AU) | Audio re-encode (similar to image re-encode) | ⚠️ Not implemented |
| Silence interval timing | Hard to detect without specialized analysis | ❌ |
| MIDI SysEx embedding | N/A — we don't process MIDI | ✅ N/A |

**Risk assessment:** Low. Audio comes from ElevenLabs (trusted API), not from untrusted external sources. If we ever process untrusted audio, re-encode through lossy codec (MP3/AAC) to strip LSB.

### Network — PLANNED SANDBOX CONTROL

| Technique | Defense | Status |
|-----------|---------|--------|
| DNS tunneling | In `Filtered` container mode, `DomainProxy` rejects raw IP addresses and only forwards to allowlisted domains; the container's `HTTP_PROXY`/`HTTPS_PROXY` env vars target the proxy socket. The container does not configure an in-VM resolver — name resolution effectively traverses the proxy. | ✅ Implemented (conditional on `container` feature + `NetworkMode::Filtered`) |
| ICMP payload injection | The `--internal` Apple Containers network mode (used in `Filtered`) blocks DNS and TCP at the platform level; ICMP egress is **not** Rust-enforced and depends on the platform's `--internal` semantics. | ✅ Implemented (conditional, platform-enforced — sigil does not enforce ICMP semantics in code) |
| TCP covert channels | `DomainProxy` accepts both HTTP CONNECT and plain HTTP forwarding to allowlisted domains; arbitrary destinations off the allowlist have no path out. CONNECT can target any port on an allowlisted domain. | ⚠️ Partial — egress is bounded by the allowlist, but allowlisted-domain ports are not further restricted |
| HTTP header smuggling | Allowlisted egress via the proxy bounds the destination set; smuggling against the proxy's own HTTP parser remains the residual surface. | ⚠️ Partial (egress bounded; proxy-parser smuggling residual) |

**Risk assessment:** Egress controls are present in the container backend (`DomainProxy` + Apple Containers `--internal`), conditional on the `container` feature and `NetworkMode::Filtered`. The `Internal` and `Full` modes either block all egress or allow unrestricted egress; only `Filtered` engages the allowlist.

### Code — RELEVANT (agents read/write code constantly)

| Technique | Defense | Status |
|-----------|---------|--------|
| Python/JS/C/CSS/Shell stego comments | Agents process code natively — no sanitization layer | ❌ Not defended |
| Zero-width chars in docstrings | strip-invisible would catch if applied to code | ⚠️ Only if we sanitize code content |
| LaTeX hidden text | Low risk — agents rarely process LaTeX | ✅ Low priority |

**Risk assessment:** Medium. Agents read code from repos and the web. A malicious repo could embed stego instructions in code comments. Defense: apply strip-invisible to code content the agent ingests from external sources (not project code — that would be too noisy).

---

## Defense Pipeline (Recommended)

```
External content enters agent context
  │
  ├─ TEXT (bridge messages, session output, web text)
  │   └─ strip-invisible (zero-width, homoglyphs, variation selectors,
  │      control chars, directional overrides, combining diacritics)
  │
  ├─ HTML/WEB (fetched pages)
  │   └─ Strip: comments, hidden elements, aria-labels, off-screen text
  │   └─ Normalize: JSON Unicode escapes, Markdown comments
  │   └─ Tag: source domain + timestamp for provenance
  │
  ├─ IMAGES (downloaded/generated)
  │   └─ Strip: all EXIF/XMP/tEXt metadata
  │   └─ Resize: 99% (breaks pixel alignment)
  │   └─ Re-encode: JPEG quality 85 (destroys LSB, disrupts DCT/F5)
  │   └─ Optional: ALLSIGHT-style chi-square analysis → log findings
  │
  ├─ AUDIO (if from untrusted source)
  │   └─ Re-encode through lossy codec (MP3/AAC)
  │
  └─ CODE (from external repos/web)
      └─ strip-invisible on comments and string literals
      └─ Flag: unusual Unicode in code files
```

## Red-Team Testing Plan

Use ST3GG to test our defenses:

1. **Text:** Encode test payloads with all 8 text techniques → verify strip-invisible catches them
2. **Images:** Create stego images with LSB, DCT, F5, metadata → verify re-encode pipeline strips them
3. **HTML:** Create pages with hidden elements, comments, aria-labels → verify WebFetch sanitizer strips them
4. **Code:** Create repos with stego comments → verify code sanitizer catches them
5. **End-to-end:** Embed a "call this URL" instruction via each technique → verify the agent never calls it

ST3GG is AGPL — use it for testing only, don't bundle or port code directly. Port the detection *logic* (algorithms are well-known, not copyrightable).

---

## What We Still Can't Defend Against

1. **Adversarial perturbations optimized for robustness** — survive JPEG re-encode + resize. Research-grade, unlikely in the wild against our specific setup.
2. **Content from trusted, allowlisted domains that is itself compromised** — if api.anthropic.com serves poisoned content, we have bigger problems.
3. **Sophisticated code stego that mimics legitimate patterns** — a comment that looks like a normal TODO but encodes instructions. No automated detection can distinguish this from real code.

---

*References:*
- *ST3GG: https://github.com/elder-plinius/ST3GG (112 techniques, ALLSIGHT detection engine)*
- *AI Agent Traps: Franklin et al., Google DeepMind, 2026*
- *strip-invisible: ~/.local/bin/strip-invisible (11/13 text stego coverage)*
