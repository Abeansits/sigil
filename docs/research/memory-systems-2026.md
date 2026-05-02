# Agent Memory Systems — Current State

**Date:** April 9, 2026
**Audience:** Sigil / conductor / orchestration design
**Thesis:** The storage layer is not the main problem anymore. The winning systems are getting better at memory *discipline*: when to write, what to write, what stays read-only, what gets consolidated, and what gets reloaded after compaction or a fresh session.

## Executive Summary

The state of the art in April 2026 is not "one magical memory database." The practical winners are hybrid systems with:

- a small amount of explicit, durable identity and preference memory
- a separate mutable state object for current work
- an append-only event stream or transcript history
- a consolidation step that turns noisy episodes into a short list of durable learnings
- scoped retrieval and strict write permissions

The biggest shift since early 2026 is that more systems now expose memory as part of the agent runtime itself, not as an afterthought bolted onto RAG. Letta has moved further toward memory-native agents and file-backed context management. Google now has first-party memory primitives in ADK plus managed `VertexAiMemoryBankService`. OpenAI has pushed memory from passive personalization toward background work with ChatGPT Pulse. Anthropic's public Claude Code surface still looks much simpler: file-based `CLAUDE.md` memory plus lifecycle hooks, with no official public documentation for an `autoDream`-style consolidation system.

The practical lesson for Sigil is straightforward: keep the flat files. Fix the lifecycle.

## What Changed Since Early 2026

### Letta

Letta's architecture has continued moving away from "memory as a special sidecar tool" and toward "memory as the agent's native working environment."

- Current Letta Code docs say **MemFS is the new memory system**, while "memory blocks" are now labeled **legacy**. MemFS lets agents edit memory through normal bash/file tools and versions memory with git for rollbacks, changelogs, and parallel coordination via worktrees. Source: [Letta Memory docs](https://docs.letta.com/letta-code/memory/).
- Letta's April 2, 2026 post, [Context Constitution](https://www.letta.com/blog/context-constitution), makes the company direction very explicit: durable token-space context, active context management, and "memory-native models" rather than stateless prompt stuffing.
- The associated product direction is visible in the ADE docs, which emphasize inspecting memory, state, prompts, and tool execution together rather than treating memory as an external vector store. Source: [ADE docs](https://docs.letta.com/memory).

Practical read: Letta has doubled down on memory as a first-class operating system concern. The notable shift is not "better retrieval," it is a stronger bias toward editable, versioned, inspectable context state.

### Claude Code / Anthropic

As of April 9, 2026, Anthropic's **public** Claude Code memory surface still looks intentionally simple and local-first.

- Claude Code documents a four-level memory hierarchy via `CLAUDE.md`: enterprise, project, user, and local/project-local memory. Source: [Manage Claude's memory](https://docs.anthropic.com/en/docs/claude-code/memory).
- Claude Code also exposes lifecycle hooks including `PreCompact`, `SessionStart`, `SessionEnd`, `Stop`, and `SubagentStop`. Source: [Hooks guide](https://docs.anthropic.com/en/docs/claude-code/hooks-guide).

I did **not** find any official Anthropic docs or announcements on `anthropic.com` or `docs.anthropic.com` that describe a public `autoDream` memory consolidation feature. That does not prove nothing internal exists, but it does mean the public product story is still: editable markdown memory files plus hook points where users can build their own discipline.

Practical read: Claude Code is notable less for a sophisticated built-in memory engine and more for giving developers clean lifecycle triggers to implement their own memory behavior.

### OpenAI

OpenAI's memory story is now clearly **hybrid** rather than purely structured or purely unstructured.

- ChatGPT memory works in two ways: **Saved Memories** and **Chat History reference**. Saved memories are explicit durable facts/preferences; chat history reference is broader, more opportunistic reuse of prior conversations. Source: [What is Memory?](https://help.openai.com/en/articles/8983136-what-is-memory).
- OpenAI's help docs also say ChatGPT can use memories to inform web search queries. Same source.
- ChatGPT Pulse extends this further: it performs **daily asynchronous research** based on past chats, memories, and feedback, then delivers results the next day. Pulse requires memory to be on. Source: [ChatGPT Pulse](https://help.openai.com/ja-jp/articles/12293630-chatgpt-pulse).
- On the API side, OpenAI exposes **conversation state** for short-horizon continuity via `previous_response_id` / conversation handling, but not a first-party long-term agent memory system equivalent to Letta or Vertex AI Memory Bank. Source: [Responses API reference](https://platform.openai.com/docs/api-reference/responses/retrieve).

Inference: OpenAI's user-facing memory is a mix of explicit profile-like memory plus opaque retrieval over prior conversations. It is more structured than a raw transcript dump, but less developer-transparent than file-backed systems like Claude Code or Letta MemFS.

### Google / Gemini

Google now has real memory primitives in its agent stack.

- In ADK, the `Session` object already includes **`state`** and **`events`**, making session memory part of the framework baseline rather than an add-on. Source: [ADK Session docs](https://google.github.io/adk-docs/sessions/session/).
- ADK also documents a dedicated memory layer, including **`VertexAiMemoryBankService`**, which can generate memories from session events at the end of a conversation and later retrieve them by search query. Source: [ADK Memory docs](https://google.github.io/adk-docs/sessions/memory/).

Practical read: Google's design is explicitly layered:

- session-local mutable state
- event history
- optional managed long-term memory service

That is a very sensible decomposition.

### New Papers / Frameworks Worth Caring About

Not every paper matters here. These do:

- [Memori: A Persistent Memory Layer for Efficient, Context-Aware LLM Agents](https://arxiv.org/abs/2603.19935) (submitted March 20, 2026) argues for turning dialogue into compact structured representations such as semantic triples plus summaries, instead of repeatedly injecting raw transcripts. The paper reports strong LoCoMo results with much lower token use.
- [CrewAI Memory docs](https://docs.crewai.com/en/concepts/memory) show a production framework direction: one unified memory API, hierarchical scopes, automatic fact extraction after tasks, and recall before tasks using semantic + recency + importance scoring.
- [LangChain Deep Agents memory docs](https://docs.langchain.com/oss/python/deepagents/memory) are especially practical because they treat memory as files in scoped namespaces, add background consolidation and cron, distinguish read-only vs writable memory, and warn explicitly about shared-memory poisoning and concurrent writes.
- [AutoGen memory docs](https://microsoft.github.io/autogen/0.4.8/user-guide/agentchat-user-guide/memory.html) and the [AutoGen memory protocol reference](https://microsoft.github.io/autogen/stable/reference/python/autogen_core.memory.html) matter because they show the opposite end of the spectrum: a thin abstraction where storage can be a list, database, or file system, and behavior is mostly up to the app.
- [Mem0 docs](https://docs.mem0.ai/) remain relevant as an independent "memory layer" product, but the strongest public evidence from the current landscape still points toward hybrid designs and disciplined triggers, not "just add vector memory."

## Trends

### 1. Structured vs Unstructured

The strongest pattern is **hybrid memory**.

- Structured works best for identity, preferences, user settings, workflow state, approvals, and "current truth."
- Unstructured or semi-structured works best for episodes, observations, transcripts, and candidate learnings.
- The systems that feel mature now separate these instead of forcing one storage model to do everything.

Verdict: use structured state for anything the runtime must reason over deterministically, and unstructured text only for evidence, history, and long-form learnings.

### 2. Local vs Cloud Storage

The split is becoming clearer:

- local/file-backed memory is favored for developer tooling, auditability, portability, and trust
- cloud-managed memory is favored when many sessions, users, or services need centralized retrieval

Claude Code and Letta both validate local/file-backed memory. Google validates managed cloud memory. The likely long-term pattern is local canonical state plus optional searchable cloud index, not full replacement of one by the other.

### 3. Append-Only Event Logs vs Mutable State

The best designs use **both**.

- append-only logs are good for audit, reconstruction, and later consolidation
- mutable state is good for current truth and resumability

This is exactly how Sigil already thinks about many other systems. Memory should follow the same rule.

### 4. Embedding Retrieval vs Keyword / Grep / FTS

The trend is away from embedding-only memory.

- embeddings help with fuzzy semantic recall
- keyword search and FTS are better for determinism, debugging, exact recall, and small local corpora
- metadata filters and scoped namespaces matter more than ever

If the corpus is "a handful of markdown files plus logs," grep/FTS is often the best first retrieval layer. Embeddings are useful later, not foundational.

### 5. Consolidation Patterns

Memory consolidation is becoming a real lifecycle phase, not a vague aspiration.

Common patterns:

- write candidate memory after actions or tasks
- reload state on session start or after compaction
- consolidate on session end, idle, or nightly cron
- keep shared memory harder to write than personal memory
- deduplicate and merge aggressively

The most important operational detail is idempotence. Running consolidation twice should not keep appending near-duplicates.

### 6. Cross-Session Memory in Frameworks

Frameworks are converging on a few ideas:

- **CrewAI:** auto-write after tasks, auto-recall before tasks, scope tree, weighted ranking.
- **LangGraph / Deep Agents:** namespace-backed memory, background consolidation, read-only vs writable paths, human approval for sensitive writes.
- **AutoGen:** protocol first, behavior second. Good abstraction, but you still have to design the policy.
- **Google ADK:** session state + events + optional managed memory bank.

The shared lesson is not "everyone solved memory." It is "everyone ended up needing explicit scopes, lifecycle hooks, and write controls."

## What Actually Works in Production

### Reliable Patterns

These look meaningfully production-credible:

- a small, explicit user/profile memory
- a separate structured state object for active work
- append-only events feeding a slower consolidation pass
- scoped memory namespaces
- read-only policy/identity memory
- local text search / FTS for small memory corpora
- human review or app-level policy for shared-memory writes

### Patterns That Still Look Fragile

- letting the model freely rewrite shared long-term memory during normal execution
- vector-only retrieval with no exact-match or metadata guardrails
- using raw conversation transcripts as durable memory
- nightly "append learnings" jobs without deduplication or merge logic
- one global memory pool shared by many agents/users

### Failure Modes

The same problems keep showing up:

- **stale memory:** old preferences or no-longer-true facts remain "sticky"
- **context pollution:** low-value trivia crowds out important state
- **wrong recall:** semantically similar but incorrect memory gets retrieved
- **memory poisoning:** a compromised or low-trust session writes instructions future runs obey
- **duplicate learnings:** repeated consolidations keep re-adding the same lesson
- **cross-identity leakage:** one user's context appears in another user's session
- **last-write-wins conflicts:** shared mutable memory gets clobbered

### Simple vs Complex

The evidence so far favors **simple architecture with disciplined behavior** over clever retrieval alone.

The useful "simple" pattern is:

1. durable profile / identity memory
2. structured current state
3. append-only episodes
4. periodic consolidation
5. narrow reload at resume time

That beats many fancy systems that jump directly to embeddings or giant context windows.

## Hooks and Lifecycle Triggers

This is where the strongest transferable design pattern lives.

### Reload After Compaction / Reset

Other systems increasingly rely on explicit reload points:

- Claude Code exposes `PreCompact` and `SessionStart` hooks.
- Google ADK models sessions as resumable objects with persisted `state` and `events`.
- LangChain Deep Agents explicitly supports background consolidation plus scoped memory reload.

Good reload recipe:

- load read-only identity/instructions first
- load structured current state second
- load a tiny number of relevant learnings third
- load recent or task-relevant episodes last

Do **not** reload the whole historical memory every time.

### Automatic Memory Discipline

The best write triggers are narrow and mechanical:

- after an action completes
- after a task finishes
- before compaction
- at session end
- on idle / nightly maintenance

The worst trigger is "whenever the model feels like remembering something."

### Identity Persistence

The cleanest systems isolate identity from everything else.

- identity and policy should be durable and hard to mutate
- state should be mutable and schema-checked
- learnings should be distilled and reviewable
- episodes should be append-only

This maps directly onto Sigil's current worldview.

## Recommendations for Sigil

### Keep the Flat Files

Do not replace `SOUL.md`, `OPS.md`, `state.json`, and `LEARNINGS.md` with a vector database just because everyone says "memory."

Those files are already close to the right abstraction:

- `SOUL.md` = durable identity
- `OPS.md` = durable operating policy
- `state.json` = structured current truth
- `LEARNINGS.md` = distilled durable learnings

The missing piece is the **control plane around them**.

### Add One More Layer: Episodic Memory Feed

Sigil needs an append-only episodic feed that sits *before* `LEARNINGS.md`.

Best option: reuse the existing audit/event machinery where possible.

What to record:

- important actions taken
- tool outcomes
- approvals granted / denied
- user corrections
- session-end summaries
- "candidate learning" events

This can be JSONL. It does not need to be fancy.

### Define Strict Write Paths

Recommended write rules:

- `SOUL.md`: read-only except explicit human-authorized edits
- `OPS.md`: read-mostly, human-reviewed edits only
- `state.json`: machine-writable, schema-checked, updated often
- `LEARNINGS.md`: machine-proposed, human-approved or threshold-promoted
- episodic log: append-only, cheap to write, never treated as canonical truth by itself

### Add Lifecycle Triggers

Minimum useful trigger set:

1. **SessionStart / resume**
   Reload `SOUL.md`, `OPS.md`, `state.json`, and only the most relevant learnings for the current task.
2. **PostAction / PostToolUse**
   Append a structured episode or candidate-learning event. Do not edit `LEARNINGS.md` directly here.
3. **PreCompact**
   Snapshot active task state into `state.json`, then compute a compact resume bundle.
4. **SessionEnd / Stop**
   Distill recent episodes into state updates plus candidate learnings.
5. **Idle / nightly consolidation**
   Deduplicate, merge, prune, expire, and promote learnings.

This is the real fix.

### Use Search in This Order

For Sigil's likely corpus size, retrieval should probably be:

1. exact file reads for canonical state
2. keyword / grep / SQLite FTS across memory files and episodic logs
3. optional embeddings later, only if recall quality is still poor

That keeps memory inspectable and debuggable.

### Make Consolidation Conservative

The dreamer/consolidator should:

- read all existing learnings before writing
- merge similar lessons
- remove superseded lessons
- attach provenance to promoted learnings
- be idempotent
- prefer "update state" over "append another note"

### Treat Shared Memory as a Security Boundary

Shared memory is not just a UX feature. It is a privileged surface.

Sigil should:

- log every persistent memory write with `ActionOrigin`
- require higher trust or human approval for writes to shared durable memory
- prevent sandboxed/low-trust sessions from directly editing conductor memory
- hash or otherwise integrity-check canonical memory files

This matches the concerns already described in [docs/AGENT-TRAPS-DEFENSE.md](../AGENT-TRAPS-DEFENSE.md).

## Concrete Build Order

### Phase 1: Fix Behavior Without Changing Storage

- add explicit memory lifecycle hooks to the conductor/session runtime
- update `state.json` at stable checkpoints
- append episodes/candidate learnings to JSONL
- reload a deterministic resume bundle after compaction or session restart

### Phase 2: Add Better Retrieval

- build a local SQLite FTS index over `SOUL.md`, `OPS.md`, `LEARNINGS.md`, `state.json`, and episodic logs
- support scoped queries by session, user, conductor, and topic

### Phase 3: Add Consolidation

- nightly or idle-time consolidator
- dedup / merge / expiry rules
- promote repeated candidate learnings into `LEARNINGS.md`

### Phase 4: Add Optional Semantic Recall

- embeddings only if FTS + metadata are not enough
- never let embeddings become the sole source of truth

## Bottom Line

The current landscape does **not** say "replace flat files with a memory platform."

It says:

- separate identity, state, episodes, and learnings
- make writes policy-driven
- reload memory intentionally after compaction/reset
- consolidate in the background
- keep retrieval simple until complexity is justified

## Source Links

### Vendor / product docs

- Letta: [Memory docs](https://docs.letta.com/letta-code/memory/)
- Letta: [Agent Development Environment docs](https://docs.letta.com/memory)
- Letta: [Context Constitution](https://www.letta.com/blog/context-constitution)
- Anthropic: [Manage Claude's memory](https://docs.anthropic.com/en/docs/claude-code/memory)
- Anthropic: [Claude Code hooks guide](https://docs.anthropic.com/en/docs/claude-code/hooks-guide)
- OpenAI: [What is Memory?](https://help.openai.com/en/articles/8983136-what-is-memory)
- OpenAI: [ChatGPT Pulse](https://help.openai.com/ja-jp/articles/12293630-chatgpt-pulse)
- OpenAI: [Responses API reference](https://platform.openai.com/docs/api-reference/responses/retrieve)
- Google ADK: [Session docs](https://google.github.io/adk-docs/sessions/session/)
- Google ADK: [Memory docs](https://google.github.io/adk-docs/sessions/memory/)

### Framework docs

- CrewAI: [Memory](https://docs.crewai.com/en/concepts/memory)
- LangChain Deep Agents: [Memory](https://docs.langchain.com/oss/python/deepagents/memory)
- AutoGen: [Memory user guide](https://microsoft.github.io/autogen/0.4.8/user-guide/agentchat-user-guide/memory.html)
- AutoGen: [Memory protocol reference](https://microsoft.github.io/autogen/stable/reference/python/autogen_core.memory.html)
- Mem0: [Docs](https://docs.mem0.ai/)

### Paper

- Memori: [arXiv:2603.19935](https://arxiv.org/abs/2603.19935)
