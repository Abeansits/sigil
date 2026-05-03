# Agent Traps Defense Matrix

**Source:** "AI Agent Traps" — Franklin et al., Google DeepMind, 2026
**Purpose:** Map each trap category against sigil defenses. Identify what we guard against, what we can't yet, and what we should watch.
**Status note (2026-05-02):** This file is a target-state threat-modeling document. The current workspace implements bridge normalization, sender allowlisting, rate limiting, trust-zone checks, grant persistence, CLI/conductor audit logging, container isolation (`ContainerRuntime` + `DomainProxy`, behind the `container` feature gate), Phase 1 external-content sanitization (`sigil-content` — plain/HTML/Markdown/JSON paths) wired through `ActionService::dispatch_fetch_external_content` and the MCP `fetch_url` tool when those servers are constructed with a sanitizer + fetcher, and `FatigueGuard` enforcement on the approval flow. It does not yet implement memory-write controls or media (image/audio/PDF) sanitization. Status flags below use the convention: ✅ Implemented • ✅ Implemented (conditional, gated on container filtered mode or sanitizer-configured server) • ⚠️ Partial • ❌ Not defended at our layer.

---

## 1. Content Injection Traps (Target: Perception)

*Exploiting the gap between human-visible and machine-parsed content to embed hidden commands.*

| Trap | Description | Our Defense | Status |
|------|------------|-------------|--------|
| **Web-Standard Obfuscation** | Hidden instructions in HTML comments, CSS `display:none`, `aria-label` tags, off-screen positioned text | Phase 1 of the `sigil-content` HTML pipeline strips `<script>`/`<style>`/`<template>`/`<noscript>` subtrees, HTML comments, `<title>`/`<meta>`, elements with the `hidden` attribute, elements with inline `display:none` / `visibility:hidden|collapse` / `opacity:0` (and class-based hidden resolved against inline `<style>` blocks), and the `aria-label` / `title` / non-image `alt` attributes. Bridge text is also sanitized. Positional off-screen CSS (e.g. negative `text-indent`, off-viewport `position:absolute`) is **not** detected. | ✅ Implemented (conditional) for HTML/Markdown/JSON/plain ingest when the conductor or MCP server is constructed with a sanitizer + fetcher (default is `DisabledFetcher`); positional off-screen CSS and image/audio/PDF stay on Phase 2. |
| **Dynamic Cloaking** | Servers detect agent visitors (via browser fingerprinting, user-agent, IP) and serve different content | No direct current defense. Future sandbox/network allowlists may narrow exposure, but they would not solve server-side cloaking. | ❌ Can't defend fully — this is server-side. We'd need a trusted proxy that strips or flags suspicious divergence. |
| **Steganographic Payloads** | Malicious instructions encoded in image pixel data, audio perturbations | Agents process images/audio as part of work, and the current workspace has no dedicated media sanitization pipeline. | ❌ Can't defend at our layer — this requires model-level robustness plus future media sanitization. |
| **Syntactic Masking** | Instructions hidden in Markdown link text, LaTeX, formatting syntax | Our session output sanitizer flags suspicious patterns ("SYSTEM:", base64 blocks). But formatting-level masking is hard to detect. | ⚠️ Partial — we catch obvious markers but not sophisticated syntactic masking. |

### What to add to sigil:
- **WebFetch output sanitization:** When an agent fetches web content, the runtime adapter should strip HTML comments, hidden elements, and metadata before the content enters the agent's context. This is a `ToolAdapter` responsibility.
- **Content provenance tagging:** Tag all external content with source domain and fetch timestamp so the audit trail can trace which content influenced which action.

### Current limitations (can't fully solve):
- Dynamic cloaking is server-side — we can't control what trusted domains serve.
- Steganographic payloads in media files are a model-level problem. The current workspace also lacks a media-sanitization pipeline, so this remains mostly future work.
- Sophisticated syntactic masking that uses valid formatting is hard to detect without model-level understanding.

---

## 2. Semantic Manipulation Traps (Target: Reasoning)

*Corrupting reasoning without issuing overt commands.*

| Trap | Description | Our Defense | Status |
|------|------------|-------------|--------|
| **Biased Phrasing & Framing** | Saturating source content with sentiment-laden or authoritative language to bias the agent's synthesis | No defense. Agents process external content at face value. | ❌ Can't defend at our layer — this is a model reasoning problem. |
| **Oversight & Critic Evasion** | Wrapping malicious instructions in "security audit," "educational," or "red-teaming" framing to bypass safety filters | No defense beyond model's own alignment. | ❌ Model-level problem. Container isolation limits what a compromised agent can do. |
| **Persona Hyperstition** | Seeding narratives about a model's identity that re-enter via retrieval, causing self-reinforcing behavior | Our SOUL.md files define conductor identity. But if external content poisons the narrative... | ⚠️ Partial — our explicit SOUL.md anchors identity, but a sophisticated attack could still shift behavior through accumulated context. |

### What to add to sigil:
- **Nothing actionable at the infrastructure level.** These are model reasoning vulnerabilities.
- **Midflight cross-checks:** For high-stakes decisions (deployments, financial, public-facing content), run midflight to get a second opinion from a different model. Different models have different susceptibilities.

### Current limitations:
- Semantic manipulation bypasses all infrastructure defenses. If the model's reasoning is corrupted, the correct-looking Action will be generated with the correct-looking justification.
- This is where the Human-in-the-Loop approval gates matter — human judgment catches what automated systems can't.

---

## 3. Cognitive State Traps (Target: Memory & Learning)

*Corrupting long-term memory, knowledge bases, and learned behavioral policies.*

| Trap | Description | Our Defense | Status |
|------|------------|-------------|--------|
| **RAG Knowledge Poisoning** | Injecting fabricated content into retrieval corpora so agents treat it as fact | We don't use RAG currently. Our memory is file-based (LEARNINGS.md, OPS.md, state.json). | ✅ Low risk for now — no external retrieval corpus. If we add RAG later, this becomes critical. |
| **Latent Memory Poisoning** | Injecting innocuous data into memory stores that becomes malicious in future context | Our conductors write to LEARNINGS.md and state.json. A compromised agent could write poisoned learnings. | ⚠️ Real risk — a compromised session could write malicious patterns to LEARNINGS.md that a conductor later follows. |
| **Contextual Learning Traps** | Corrupting few-shot demonstrations or reward signals to steer in-context learning | Our conductors learn from auto-response outcomes (LEARNINGS.md promotion pattern). A carefully crafted sequence of interactions could steer this. | ⚠️ Real risk — our self-improvement loop (auto_response_ok/wrong → promoted patterns) could be gamed. |

### What to add to sigil:
- **Memory write audit:** Every write to persistent memory files (LEARNINGS.md, OPS.md, state.json) gets logged to the audit trail with the originating session and ActionOrigin. If a Slack-originated session writes to LEARNINGS.md, that's flagged.
- **Memory integrity checks:** Periodic diff of memory files against last known-good state. Alert on unexpected changes. HMAC-chain the memory files, not just the audit log.
- **Container memory isolation:** Sandboxed sessions can NOT write to conductor memory files. They can only write to their own project directory. Memory updates go through the conductor (host-side) as a T2 action.

### Current limitations:
- If a trusted session is compromised (via a web-fetched content injection), the memory write has full authority. The audit trail catches it after the fact, but doesn't prevent it.
- The self-improvement loop (LEARNINGS.md promotion) is inherently vulnerable to slow poisoning. Mitigation: human review before promotion (already in OPS.md — recurrence 3+ before promotion).

---

## 4. Behavioural Control Traps (Target: Action)

*Hijacking the agent's capabilities to execute attacker goals.*

| Trap | Description | Our Defense | Status |
|------|------------|-------------|--------|
| **Embedded Jailbreak Sequences** | Adversarial prompts in external resources that override safety alignment on ingestion | Current defenses are typed actions, tier ceilings, trust-zone checks, and audit logging. Planned sandbox isolation would strengthen this considerably. | ⚠️ Partial — authority controls reduce blast radius, but runtime isolation is not implemented yet. |
| **Data Exfiltration Traps** | Inducing the agent to locate, encode, and exfiltrate data to attacker endpoints | Current defenses are policy-mediated actions, bridge allowlisting, and audit visibility. Planned sandbox/network restrictions would be the stronger containment layer. | ⚠️ Partial — the current workspace reduces privilege, but it does not yet provide container-style egress isolation. |
| **Sub-agent Spawning Traps** | Exploiting orchestrator privileges to spawn attacker-controlled sub-agents with poisoned prompts | Our conductor creates sessions. If the conductor is compromised, it could spawn malicious sessions. | ⚠️ Partial — session creation is a T2 action. Bridge-originated (Slack) messages can't create sessions. But a compromised conductor could. |

### What to add to sigil:
- **Sub-agent spawn controls:** Session creation should always log the full prompt/instructions to the audit trail. New sessions spawned by the conductor inherit the conductor's ActionOrigin chain — if the conductor was triggered by a bridge message, the spawned session carries that taint.
- **Session creation rate limit:** Max N new sessions per hour. Anomaly detection if a conductor suddenly spawns many sessions.
- **Instructions review:** When a session is created with custom instructions (not from a template), flag for review if the instructions contain suspicious patterns (URLs, credential references, "ignore previous instructions", etc.).

### Current limitations:
- A directly compromised conductor (via the operator's CLI or Telegram) has full authority to spawn sessions. The audit trail catches it, but can't prevent it.

---

## 5. Systemic Traps (Target: Multi-Agent Dynamics)

*Seeding the environment to trigger macro-level failures via correlated agent behavior.*

| Trap | Description | Our Defense | Status |
|------|------------|-------------|--------|
| **Congestion Traps** | Broadcasting signals that synchronize agents into exhaustive demand for limited resources | Low risk — we have <20 agents, not thousands. | ✅ N/A at our scale. Budget guard (per-session ceiling) would catch runaway resource consumption. |
| **Interdependence Cascades** | Triggering self-reinforcing failure loops across interdependent agents | Our conductor pattern is hub-and-spoke, not peer-to-peer. Agents don't react to each other's outputs. | ✅ Low risk — agents are isolated. The conductor mediates all inter-agent communication. |
| **Tacit Collusion** | Embedding environmental signals to coordinate anti-competitive behavior | N/A — we're not in a competitive multi-agent economy. | ✅ N/A for our use case. |
| **Compositional Fragment Traps** | Partitioning a malicious payload across multiple benign-looking sources that reconstitute when aggregated | A conductor aggregates output from multiple sessions. Fragments across sessions could reconstitute. | ⚠️ Theoretical risk — low probability for our setup, but the architecture does aggregate multi-session data. |
| **Sybil Attacks** | Fabricating multiple agent identities to influence collective decisions | N/A — we don't have democratic agent decision-making. | ✅ N/A for our use case. |

### What to add to sigil:
- Nothing for MVP. These are relevant at scale (hundreds/thousands of agents).
- **Future consideration:** If we add Ting-like multi-model deliberation to automated workflows, Sybil attacks and compositional fragments become relevant.

---

## 6. Human-in-the-Loop Traps (Target: Human Overseer)

*Using the agent to attack the human via cognitive biases.*

| Trap | Description | Our Defense | Status |
|------|------------|-------------|--------|
| **Approval Fatigue** | Generating many benign-looking approval requests to tire the human into rubber-stamping a malicious one | Our auto-deny timeout (5 min) prevents unattended requests. But a flood of legitimate requests followed by one malicious one... | ⚠️ Real risk — this is one of the most insidious attacks. If the conductor sends 20 approval requests in a row, the operator will start approving without reading. |
| **Automation Bias** | Presenting technical, benign-looking summaries that a non-expert human would likely authorize | Our conductor presents summaries to the operator. If those summaries are crafted to look safe... | ⚠️ Real risk — the operator trusts the conductor's judgment. A compromised conductor could frame malicious actions as routine. |
| **Social Engineering via Agent** | Using the agent to deliver phishing links or manipulative content to the human | Bridge messages go directly to the operator. A compromised agent's output could contain phishing. | ⚠️ Partial — the audit trail logs everything, but doesn't prevent the operator from clicking a link in a Telegram message. |

### What to add to sigil:
- **Approval request rate limit:** Max N approval requests per hour per session. If a session is generating many approval requests, flag it and pause.
- **Approval request context:** Every approval notification includes: what session requested it, what ActionOrigin triggered it, how many approvals this session has requested today, and a risk indicator based on the action's tier.
- **Cool-down after burst:** If >3 approvals in 10 minutes, enforce a 5-minute cool-down before the next approval can be granted. Forces the operator to slow down.
- **Anomaly alerting:** If a session that normally never requests approvals suddenly starts requesting them, flag it loudly.

### Current limitations:
- **Approval fatigue is fundamentally a human problem.** Technology can slow it down (rate limits, cool-downs) but can't eliminate it. The operator needs to treat approval requests with the same attention every time — which is hard.
- **Automation bias is our Achilles heel.** The conductor summarizes agent output and makes it easy for the operator to approve. The convenience that makes the system usable is the same convenience that makes it exploitable. There is no great technical fix — the best defense is awareness and the habit of reading approval details.

---

## Summary: What We Guard Against vs. What We Can't

### Target-state strong defenses (requires sandboxing + policy engine + audit):
- Data exfiltration (network allowlist + filesystem isolation)
- Embedded jailbreak blast radius (container limits what jailbroken agent can access)
- Unauthorized session creation from untrusted sources (Action enum + tier enforcement)
- Supply chain attacks (Rust-only deps, no npm/pip)
- Memory poisoning from untrusted sessions (container isolation blocks memory writes)
- Invisible Unicode / stego text injection (strip-invisible sanitization)

### ⚠️ Partial defenses (we reduce risk but can't eliminate):
- Web-standard obfuscation in fetched content (need WebFetch output sanitization)
- Latent memory poisoning from trusted sessions (audit trail detects, doesn't prevent)
- Sub-agent spawning from compromised conductor (audit + rate limit)
- Approval fatigue (rate limits + cool-down, but fundamentally human)
- Syntactic masking in formatting (we catch obvious patterns, miss sophisticated ones)

### ❌ Can't defend at our layer:
- **Dynamic cloaking** — server-side, we can't control what trusted domains serve
- **Steganographic payloads** in media — model-level problem
- **Biased phrasing / framing** — model reasoning vulnerability
- **Oversight & critic evasion** — model alignment problem
- **Automation bias** — human cognitive vulnerability, can only mitigate with awareness

---

## Action Items for sigil

### Add to proposal:
1. WebFetch output sanitization in `ToolAdapter` (strip HTML comments, hidden elements, metadata)
2. Content provenance tagging (source domain + timestamp on all external content)
3. Memory write audit (log all writes to persistent memory with ActionOrigin)
4. Container memory isolation (sandboxed sessions can't write conductor memory)
5. Sub-agent spawn logging + rate limit
6. Approval request rate limit + cool-down + anomaly detection
7. Approval notification context enrichment (origin chain, request count, risk indicator)

### Document as known limitations:
- Dynamic cloaking, steganographic payloads, semantic manipulation are model-level problems outside our control
- Approval fatigue and automation bias are human cognitive vulnerabilities — technology can slow them down but not eliminate them
- A directly compromised conductor (via the operator's own compromised device) bypasses all defenses except the audit trail

### Future research:
- WebFetch content scanning (detect hidden instructions in HTML before they enter agent context)
- Multi-model verification for high-stakes actions (midflight as a defense, not just a productivity tool)
- Memory file integrity monitoring (periodic hash verification, alert on unexpected changes)

---

*Based on: "AI Agent Traps" — Matija Franklin, Nenad Tomašev, Julian Jacobs, Joel Z. Leibo, Simon Osindero. Google DeepMind, 2026.*
