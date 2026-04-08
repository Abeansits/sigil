# CLAUDE-MD-DRAFT

This file was retired on 2026-04-07 to avoid drifting from the real agent instructions.

Use [`CLAUDE.md`](/Users/zebas/Developer/sigil/CLAUDE.md) as the authoritative source.

The important deltas that made this draft unsafe to keep around were:

- the workspace has 8 crates, not 9
- there is no `ops-container` crate
- the current runtime is tmux-only
- the CLI only exposes `status`, `session`, `worktree`, and `conductor`
- there is no `PolicyContext` type in the current codebase

If a fresh draft is needed later, regenerate it from the root `CLAUDE.md` instead of editing this file independently.
