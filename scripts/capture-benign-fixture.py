#!/usr/bin/env python3
# Canonical capture tool for the `sigil-content` benign corpus
# (`crates/sigil-content/fixtures/benign/*.txt`).
#
# Usage (from repo root):
#     ./scripts/capture-benign-fixture.py <url> > crates/sigil-content/fixtures/benign/<name>.txt
#
# Pipeline:
#   1. Fetch the URL with a realistic browser User-Agent (pages we care
#      about — MDN, Mozilla blog, 0xdf, Promptfoo, OWASP, PortSwigger —
#      reject bare `curl/*` UAs).
#   2. Parse HTML with the stdlib `html.parser`. Drop full subtrees for
#      `<script>`, `<style>`, `<noscript>`, `<head>`, `<nav>`, `<footer>`,
#      `<svg>`, `<form>`, `<aside>` — chrome that isn't part of the
#      article body.
#   3. Decode HTML entities (so `&lt;script&gt;` becomes `<script>`,
#      matching what the scanner would see after the real HTML sanitizer
#      pass at runtime).
#   4. Strip bare `<!DOCTYPE html>` and `<html …>` opener tokens. These
#      slip through from code blocks that legitimately quote full HTML
#      documents (MDN's CSP guide's meta-tag example, 0xdf's Laravel
#      error-page HTTP response dump) and trip `FMT-001` Path A of the
#      pattern scorer — Path A is currently calibrated as "a single bare
#      `<!DOCTYPE html>` / `<html>` token is definitive enough to fire a
#      High-severity finding," which misfires on security writing that
#      includes full HTML code blocks in prose.
#
#      The strip is the narrowest possible fixture-capture workaround
#      for that mis-calibration — every other HTML token (`<script>`,
#      `<iframe>`, `<meta>`, `<body>`, close tags, attribute strings…)
#      is preserved verbatim so the INJ/ENC/REP/MIX/FMT-001 Path-B/WRP
#      pattern surface is unchanged. The PR3.6 follow-up that demoted
#      FMT-001 to audit-only metadata removed the only place this strip
#      mattered for the FP-rate gate; the workaround is retained for
#      reproducibility of the existing benign-corpus captures.
#   5. Collapse runs of whitespace. Write the result to stdout.
#
# The output shape matches the existing benign fixtures (a01, a05, a06
# etc.) — whitespace-collapsed prose with code-block content inline.
# Using this script for all future benign captures keeps fixture
# provenance reproducible and auditable.
from html.parser import HTMLParser
import re
import sys
import urllib.request

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)
DROP = {"script", "style", "noscript", "head", "nav", "footer", "svg", "form", "aside"}
BREAK = {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote"}


class Extractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in DROP:
            self.skip += 1
        elif tag in BREAK:
            self.out.append(" ")

    def handle_endtag(self, tag):
        if tag in DROP and self.skip:
            self.skip -= 1
        elif tag in BREAK:
            self.out.append(" ")

    def handle_data(self, data):
        if self.skip:
            return
        self.out.append(data)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read()
        charset = _detect_charset(r, body)
    return body.decode(charset, errors="replace")


def _detect_charset(response, body: bytes) -> str:
    # 1. HTTP Content-Type charset (authoritative when present).
    ctype = response.headers.get("Content-Type", "")
    m = re.search(r"charset=([^\s;]+)", ctype, re.IGNORECASE)
    if m:
        return m.group(1).strip('"').strip("'")
    # 2. HTML meta charset — look at the first ~2KB only; past that we
    #    risk hitting decoded payloads that happen to mention "charset".
    head = body[:2048]
    try:
        head_text = head.decode("ascii", errors="ignore")
    except Exception:
        head_text = ""
    m = re.search(r'<meta[^>]+charset=["\']?([a-zA-Z0-9_\-]+)', head_text, re.IGNORECASE)
    if m:
        return m.group(1)
    # 3. Fall back to UTF-8 — modern pages default to it and decode
    #    errors are reported as replacement chars, which is loud enough
    #    to catch during fixture review.
    return "utf-8"


def normalize(html: str) -> str:
    e = Extractor()
    e.feed(html)
    text = "".join(e.out)
    text = re.sub(r"(?i)<!DOCTYPE\s+html\s*>", "", text)
    text = re.sub(r"(?i)<\s*html\b[^>]*>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def main():
    if len(sys.argv) < 2:
        print("usage: capture-benign-fixture.py <url>", file=sys.stderr)
        sys.exit(2)
    url = sys.argv[1]
    raw = sys.stdin.read() if url == "-" else fetch(url)
    sys.stdout.write(normalize(raw) + "\n")


if __name__ == "__main__":
    main()
