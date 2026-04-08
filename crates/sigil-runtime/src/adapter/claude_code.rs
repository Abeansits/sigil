use regex::Regex;
use sigil_core::ConductorMessage;
use sigil_core::protocol::{AgentSignal, Confidence, HookFormat, StatusPattern};
use sigil_core::session::SessionState;
use sigil_core::traits::ToolAdapter;

/// Adapter for Claude Code terminal sessions.
///
/// Translates conductor messages into text that Claude Code understands,
/// and parses terminal output into structured signals (observability only).
pub struct ClaudeCodeAdapter {
    patterns: Vec<StatusPattern>,
}

impl ClaudeCodeAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // Waiting indicators — Claude Code shows a prompt when ready
                // for input.
                StatusPattern {
                    state: SessionState::Waiting,
                    pattern: r"(?m)(╰─|>\s*$|What would you like)".to_owned(),
                    confidence: Confidence::Medium,
                },
                // Error indicators
                StatusPattern {
                    state: SessionState::Error,
                    pattern: r"(?mi)(^error:|panic|fatal error|segmentation fault)".to_owned(),
                    confidence: Confidence::High,
                },
                // Running indicators — tool use in progress
                StatusPattern {
                    state: SessionState::Running,
                    pattern: r"(Read\(|Edit\(|Bash\(|Write\(|Grep\(|Glob\()".to_owned(),
                    confidence: Confidence::Low,
                },
            ],
        }
    }
}

impl Default for ClaudeCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolAdapter for ClaudeCodeAdapter {
    fn status_patterns(&self) -> &[StatusPattern] {
        &self.patterns
    }

    fn hook_format(&self) -> HookFormat {
        HookFormat::ClaudeCodeHooks
    }

    #[allow(clippy::wildcard_enum_match_arm)]
    fn translate_send(&self, msg: &ConductorMessage) -> String {
        match msg {
            ConductorMessage::TaskAssignment { instructions } => instructions.clone(),
            ConductorMessage::ApprovalResponse {
                approved: true,
                constraints,
                ..
            } => match constraints {
                Some(c) if !c.is_empty() => format!("Approved. {c}"),
                _ => "Approved.".to_owned(),
            },
            ConductorMessage::ApprovalResponse {
                approved: false, ..
            } => "Denied.".to_owned(),
            ConductorMessage::StopRequest { .. } => "/stop".to_owned(),
            ConductorMessage::Ping | _ => String::new(),
        }
    }

    fn parse_output(&self, raw: &str) -> Vec<AgentSignal> {
        let mut signals = Vec::new();

        // Check the last ~20 lines for state indicators. This avoids
        // matching stale patterns from earlier in the scrollback.
        let tail: String = raw
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");

        // Completion — high confidence when Claude explicitly says it is
        // done.
        let completion_re =
            Regex::new(r"(?mi)(task complete|done\.|finished\.|completed successfully)");
        if let Ok(re) = completion_re {
            if let Some(m) = re.find(&tail) {
                signals.push(AgentSignal::CompletionSignal {
                    summary: m.as_str().to_owned(),
                });
            }
        }

        // Walk the configured patterns (waiting, error, running)
        for pat in &self.patterns {
            let re = Regex::new(&pat.pattern);
            if let Ok(re) = re {
                if re.is_match(&tail) {
                    signals.push(AgentSignal::StatusUpdate { state: pat.state });
                }
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use sigil_core::id::RequestId;

    use super::*;

    fn adapter() -> ClaudeCodeAdapter {
        ClaudeCodeAdapter::new()
    }

    // -----------------------------------------------------------------------
    // translate_send
    // -----------------------------------------------------------------------

    #[test]
    fn translate_send_task_assignment_returns_instructions() {
        let msg = ConductorMessage::TaskAssignment {
            instructions: "Build the auth flow".to_owned(),
        };
        assert_eq!(adapter().translate_send(&msg), "Build the auth flow");
    }

    #[test]
    fn translate_send_approval_approved_without_constraints() {
        let msg = ConductorMessage::ApprovalResponse {
            request_id: RequestId::new(),
            approved: true,
            constraints: None,
        };
        assert_eq!(adapter().translate_send(&msg), "Approved.");
    }

    #[test]
    fn translate_send_approval_approved_with_constraints() {
        let msg = ConductorMessage::ApprovalResponse {
            request_id: RequestId::new(),
            approved: true,
            constraints: Some("Only in staging".to_owned()),
        };
        assert_eq!(adapter().translate_send(&msg), "Approved. Only in staging");
    }

    #[test]
    fn translate_send_approval_denied() {
        let msg = ConductorMessage::ApprovalResponse {
            request_id: RequestId::new(),
            approved: false,
            constraints: None,
        };
        assert_eq!(adapter().translate_send(&msg), "Denied.");
    }

    #[test]
    fn translate_send_stop_request_returns_stop() {
        let msg = ConductorMessage::StopRequest {
            reason: "user requested".to_owned(),
        };
        assert_eq!(adapter().translate_send(&msg), "/stop");
    }

    #[test]
    fn translate_send_ping_returns_empty() {
        let msg = ConductorMessage::Ping;
        assert_eq!(adapter().translate_send(&msg), "");
    }

    // -----------------------------------------------------------------------
    // parse_output
    // -----------------------------------------------------------------------

    #[test]
    fn parse_output_detects_waiting_prompt() {
        let output = "Some output\n╰─ ";
        let signals = adapter().parse_output(output);
        assert!(
            signals.iter().any(|s| matches!(
                s,
                AgentSignal::StatusUpdate {
                    state: SessionState::Waiting
                }
            )),
            "expected waiting signal, got {signals:?}"
        );
    }

    #[test]
    fn parse_output_detects_error_state() {
        let output = "working...\nError: something broke\n";
        let signals = adapter().parse_output(output);
        assert!(
            signals.iter().any(|s| matches!(
                s,
                AgentSignal::StatusUpdate {
                    state: SessionState::Error
                }
            )),
            "expected error signal, got {signals:?}"
        );
    }

    #[test]
    fn parse_output_detects_running_tool_use() {
        let output = "Read(/src/lib.rs)\nprocessing...";
        let signals = adapter().parse_output(output);
        assert!(
            signals.iter().any(|s| matches!(
                s,
                AgentSignal::StatusUpdate {
                    state: SessionState::Running
                }
            )),
            "expected running signal, got {signals:?}"
        );
    }

    #[test]
    fn parse_output_detects_completion() {
        let output = "All changes applied.\nTask complete.";
        let signals = adapter().parse_output(output);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, AgentSignal::CompletionSignal { .. })),
            "expected completion signal, got {signals:?}"
        );
    }

    #[test]
    fn parse_output_returns_empty_for_ambiguous_output() {
        let output = "loading modules\ncompiling crate";
        let signals = adapter().parse_output(output);
        assert!(
            signals.is_empty(),
            "expected no signals for ambiguous output, got {signals:?}"
        );
    }

    #[test]
    fn parse_output_detects_panic() {
        let output = "thread 'main' panicked at 'oops'\n";
        let signals = adapter().parse_output(output);
        assert_matches!(
            signals.as_slice(),
            [AgentSignal::StatusUpdate {
                state: SessionState::Error
            }]
        );
    }
}
