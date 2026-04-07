# X/Twitter First Post — Draft v1

> I asked Claude to review a PR that 141 engineers already approved and merged into the Swift compiler.
>
> It found 10 issues. Impressive.
>
> Then I had 3 AI models debate the same code. They found 7 issues — and proved 3 of Claude's findings were wrong.
>
> One model even caught that another's suggested fix wouldn't actually work.
>
> That's what cross-examination does. One model gives you an answer. Structured disagreement gives you a decision.
>
> Open source, Rust, works with any model:
> github.com/Abeansits/ting
>
> [terminal screenshot]

## Source data
- Swift PR #32291 (C++ destructor support), 141 reviews, merged
- Baseline: single Claude Opus 4.6 → 10 findings
- Forum: Claude + OpenCode + (Codex timed out R1, joined R2) → 7 findings + 3 false positives caught
- Eval session: agora-2026-03-29-b45c068e
