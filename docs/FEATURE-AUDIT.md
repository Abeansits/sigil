# Agent-Deck Feature Audit

Say **keep**, **drop**, or **modify** for each. Call out numbers like "keep 1-5, drop 6, modify 7".

---

## A. Session Lifecycle

1. Add session (specify path, title, group, tool)
2. Launch session (add + start + send initial message in one step)
3. Start / Stop / Restart session
4. Remove session
5. Rename session
6. Fork session (clone Claude session with context preserved)
7. Attach to session (interactive tmux attach)
8. Session auto-detect (knows which session you're in from tmux env)

## B. Session Communication

9. Send message to session (with wait/no-wait options)
10. Read session output (last response, quiet mode)
11. Send output from one session as message to another (cross-session relay)

## C. Session Metadata & Status

12. Status detection via hooks (Claude/Gemini/Codex send events on state change)
13. Status detection via tmux polling (fallback when hooks unavailable)
14. Session states: running, waiting, idle, error, stopped
15. Per-session notes (user-editable, persistent)
16. Session metadata: title, path, group, tool, parent, created_at, last_accessed
17. Session resolution: by ID, title, fuzzy match, prefix, or auto-detect from tmux

## D. Parent-Child & Groups

18. Parent-child session linking (sub-sessions)
19. Child event notifications (parent gets notified when child is waiting)
20. Group hierarchy (nested groups, sessions organized in tree)
21. Move sessions between groups
22. Group reordering (up/down/position)

## E. Profiles

23. Multiple isolated profiles (separate session DB per profile)
24. Per-profile config overrides
25. Profile CRUD (create, delete, list, set-default)
26. Cross-profile listing (--all flag)
27. Profile-specific MCP pool configuration

## F. Conductor (Meta-Agent Orchestration)

28. Named conductor instances
29. Per-conductor instructions file + CLAUDE.md
30. Per-conductor policy/learnings split
31. Heartbeat system (periodic check-in)
32. Child waiting event notifications
33. Auto-response capabilities
34. Multi-conductor per profile
35. Conductor setup/teardown commands

## G. Messaging Bridges

36. Telegram bridge (bot token, user auth, voice transcription)
37. Slack bridge (socket mode, channel routing, outbox system)
38. Discord bridge (config skeleton exists, not fully built)
39. Bridge message routing to specific sessions by profile

## H. Tmux Integration

40. Each session = one tmux window in profile-specific tmux server
41. Tmux send-keys for input
42. Tmux pane capture for output
43. Custom tmux options via config
44. Keyboard protocol management (kitty protocol handling)

## I. Git Worktree Support

45. Auto-create worktree for branch on session add
46. Worktree location modes (sibling, subdirectory, custom template)
47. Worktree finish workflow (merge + remove worktree + delete session)
48. Orphaned worktree cleanup
49. Multi-repo worktree support

## J. MCP (Model Context Protocol)

50. Per-session MCP attach/detach
51. Global MCP configuration
52. MCP pool mode (HTTP server pooling for shared MCP instances)
53. MCP auto-start on session launch
54. MCP auto-consent configuration
55. MCP stdio and HTTP transports

## K. Skills System

56. Attach/detach skills per project
57. Skill source management (add/remove/list sources)
58. Skill discovery from configured sources

## L. Docker Sandbox

59. Run sessions in Docker containers (--sandbox flag)
60. Custom Docker image, CPU/memory limits, volume mounts

## M. SSH Remote

61. Run sessions on remote hosts via SSH
62. Remote working directory specification

## N. Remote Instances (Multi-Machine)

63. Add/remove remote agent-deck instances
64. List sessions across remotes
65. Attach to remote sessions
66. Install/update agent-deck on remotes

## O. Cost Tracking

67. Per-session cost tracking (token counts, model pricing)
68. Daily/weekly/monthly summaries with projections
69. Budget limits (daily/weekly/monthly, per-group)
70. Cost sync from Claude transcripts
71. Custom pricing overrides per model

## P. TUI (Terminal UI)

72. Tree view of sessions organized by groups
73. Preview pane (toggleable, configurable location/size)
74. Full keyboard shortcut system (~30 bindings)
75. Session creation wizard dialog
76. MCP manager dialog
77. Skill manager dialog
78. Notes editor
79. Search/filter across sessions
80. Theme support (dark/light/system)
81. Responsive layout

## Q. Web Interface

82. Web server alongside TUI (localhost:8420)
83. Bearer token auth
84. Read-only mode option
85. WebSocket real-time updates
86. Web push notifications (VAPID keys)

## R. OpenClaw Integration

87. Sync OpenClaw agents as sessions
88. Bridge TUI for OpenClaw agents
89. Send messages to OpenClaw agents

## S. Hook System

90. Claude Code hook handler (SessionStart, BeforeAgent, AfterAgent, Stop, etc.)
91. Gemini hooks
92. Codex notification hooks
93. Hook-based status tracking
94. Hook install/uninstall/status commands

## T. Maintenance & Operations

95. Background maintenance worker (stale cleanup, consistency checks)
96. Debug ring buffer (in-memory logs for crash dumps)
97. Debug dump command (post-mortem analysis)
98. Configurable log levels, formats, retention
99. Automatic update checking and installation
100. Uninstall command

## U. CLI Quality-of-Life

101. JSON output mode on all commands
102. Quiet mode (exit codes only, for scripting)
103. Fuzzy matching for session resolution
104. Helpful error messages with exit codes (0=success, 1=error, 2=not found)
105. Try command (quick experiment: find-or-create dated folder)
106. Global search across session transcripts

## V. Security (Current)

107. macOS Keychain for secrets (Telegram token)
108. Docker sandbox isolation
109. Environment variable support for sensitive config
110. Profile name validation (prevents path traversal)

---

## Features NOT in agent-deck (from our security plan / wishlist)

111. Input sanitization (strip-invisible, hidden char detection)
112. Permission tiers (owner/partner/automated/external)
113. Trust zones (trusted/semi-trusted/sandboxed)
114. Bridge-level command allowlist
115. Sender allowlist + rate limiting
116. Audit trail (append-only security log)
117. Approval gates with scoped grants + TTL
118. Network policy (read/write split)
119. Supply chain hardening (pinned deps, MCP verification)
120. WASM or container sandboxing for untrusted inputs
