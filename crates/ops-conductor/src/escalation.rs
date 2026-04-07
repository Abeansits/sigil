//! Escalation logic — decide which sessions need human attention and
//! format status reports for the bridge.

use ops_core::session::{SessionRecord, SessionState};

use crate::heartbeat::HeartbeatResult;

/// Priority level for escalation messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscalationPriority {
    /// Informational only.
    Low,
    /// Should look at when convenient.
    Medium,
    /// Needs attention soon.
    High,
}

/// A message indicating a session needs human attention.
#[derive(Clone, Debug)]
pub struct EscalationMessage {
    pub session_title: String,
    pub reason: String,
    pub priority: EscalationPriority,
}

/// Maximum time (in seconds) a session can be waiting before we escalate.
const WAIT_THRESHOLD_SECS: u64 = 600; // 10 minutes

/// Patterns in session output that suggest a decision is being requested.
const DECISION_PATTERNS: &[&str] = &[
    "?",
    "which option",
    "should I",
    "do you want",
    "please choose",
    "waiting for",
    "your decision",
    "approve",
    "confirm",
];

/// Format a status report from a heartbeat result.
///
/// Output matches the bridge protocol format:
/// ```text
/// [STATUS] 5 sessions (2 running, 1 waiting, 2 stopped)
/// AUTO: frontend - continued with existing auth middleware
/// NEED: api-fix - asking whether to target staging or prod
/// ```
pub fn format_status_report(result: &HeartbeatResult) -> String {
    let mut lines = Vec::new();

    // Summary line.
    let mut parts = Vec::new();
    if result.running > 0 {
        parts.push(format!("{} running", result.running));
    }
    if result.waiting > 0 {
        parts.push(format!("{} waiting", result.waiting));
    }
    if result.idle > 0 {
        parts.push(format!("{} idle", result.idle));
    }
    if result.error > 0 {
        parts.push(format!("{} error", result.error));
    }
    if result.stopped > 0 {
        parts.push(format!("{} stopped", result.stopped));
    }

    let summary = if parts.is_empty() {
        format!("[STATUS] {} sessions.", result.total)
    } else {
        format!("[STATUS] {} sessions ({}).", result.total, parts.join(", "))
    };
    lines.push(summary);

    // Auto-responded sessions.
    for title in &result.auto_responded {
        lines.push(format!("AUTO: {title} - auto-responded"));
    }

    // Sessions needing attention.
    for title in &result.needs_attention {
        lines.push(format!("NEED: {title} - needs attention"));
    }

    lines.join("\n")
}

/// Decide whether a waiting session should be escalated.
///
/// Rules:
/// - Error state sessions always escalate at `High` priority.
/// - Sessions waiting longer than 10 minutes escalate at `Medium`.
/// - Output containing question marks or decision-request patterns
///   escalates at `High`.
/// - Otherwise, no escalation.
pub fn should_escalate(
    session: &SessionRecord,
    output: &str,
    waiting_secs: u64,
) -> Option<EscalationMessage> {
    // Error sessions always escalate.
    if session.state == SessionState::Error {
        return Some(EscalationMessage {
            session_title: session.title.clone(),
            reason: "session is in error state".into(),
            priority: EscalationPriority::High,
        });
    }

    // Only evaluate waiting sessions.
    if session.state != SessionState::Waiting {
        return None;
    }

    // Check for decision-request patterns in output.
    let output_lower = output.to_lowercase();
    for pattern in DECISION_PATTERNS {
        if output_lower.contains(pattern) {
            return Some(EscalationMessage {
                session_title: session.title.clone(),
                reason: format!("output contains decision-request pattern: \"{pattern}\""),
                priority: EscalationPriority::High,
            });
        }
    }

    // Long wait escalation.
    if waiting_secs >= WAIT_THRESHOLD_SECS {
        return Some(EscalationMessage {
            session_title: session.title.clone(),
            reason: format!("waiting for {} minutes", waiting_secs / 60),
            priority: EscalationPriority::Medium,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ops_core::id::SessionId;
    use ops_core::session::ToolKind;
    use ops_core::trust::ExecutionClass;

    use super::*;

    fn make_session(title: &str, state: SessionState) -> SessionRecord {
        SessionRecord {
            id: SessionId::new(),
            title: title.into(),
            path: PathBuf::from("/tmp/test"),
            tool: ToolKind::ClaudeCode,
            group: None,
            parent: None,
            execution_class: ExecutionClass::OfflineWorker,
            sandboxed: true,
            state,
        }
    }

    // -- format_status_report tests --

    #[test]
    fn format_status_report_shows_counts() {
        let result = HeartbeatResult {
            total: 5,
            running: 2,
            waiting: 1,
            idle: 0,
            error: 1,
            stopped: 1,
            auto_responded: Vec::new(),
            needs_attention: Vec::new(),
        };

        let report = format_status_report(&result);
        assert!(report.contains("[STATUS]"));
        assert!(report.contains("5 sessions"));
        assert!(report.contains("2 running"));
        assert!(report.contains("1 waiting"));
        assert!(report.contains("1 error"));
        assert!(report.contains("1 stopped"));
    }

    #[test]
    fn format_status_report_with_auto_and_need() {
        let result = HeartbeatResult {
            total: 3,
            running: 1,
            waiting: 1,
            idle: 0,
            error: 1,
            stopped: 0,
            auto_responded: vec!["frontend".into()],
            needs_attention: vec!["api-fix".into()],
        };

        let report = format_status_report(&result);
        assert!(report.contains("AUTO: frontend"));
        assert!(report.contains("NEED: api-fix"));
    }

    #[test]
    fn format_status_report_empty_sessions() {
        let result = HeartbeatResult::default();
        let report = format_status_report(&result);
        assert!(report.contains("[STATUS] 0 sessions."));
    }

    #[test]
    fn format_status_report_all_running() {
        let result = HeartbeatResult {
            total: 3,
            running: 3,
            waiting: 0,
            idle: 0,
            error: 0,
            stopped: 0,
            auto_responded: Vec::new(),
            needs_attention: Vec::new(),
        };

        let report = format_status_report(&result);
        assert!(report.contains("3 sessions (3 running)"));
    }

    // -- should_escalate tests --

    #[test]
    fn escalation_on_error_state() {
        let session = make_session("broken", SessionState::Error);
        let result = should_escalate(&session, "", 0);
        assert!(result.is_some());
        let msg = result.expect("should have escalation");
        assert_eq!(msg.priority, EscalationPriority::High);
        assert!(msg.reason.contains("error state"));
    }

    #[test]
    fn escalation_on_long_wait() {
        let session = make_session("slow", SessionState::Waiting);
        // 15 minutes = 900 seconds (> 600 threshold)
        let result = should_escalate(&session, "done processing, ready for input", 900);
        assert!(result.is_some());
        let msg = result.expect("should have escalation");
        assert_eq!(msg.priority, EscalationPriority::Medium);
        assert!(msg.reason.contains("15 minutes"));
    }

    #[test]
    fn escalation_on_decision_request_in_output() {
        let session = make_session("chooser", SessionState::Waiting);
        let output = "Should I deploy to staging or production?";
        let result = should_escalate(&session, output, 30);
        assert!(result.is_some());
        let msg = result.expect("should have escalation");
        assert_eq!(msg.priority, EscalationPriority::High);
        assert!(msg.reason.contains("decision-request pattern"));
    }

    #[test]
    fn no_escalation_for_running() {
        let session = make_session("busy", SessionState::Running);
        let result = should_escalate(&session, "processing...", 0);
        assert!(result.is_none());
    }

    #[test]
    fn no_escalation_for_stopped() {
        let session = make_session("off", SessionState::Stopped);
        let result = should_escalate(&session, "", 0);
        assert!(result.is_none());
    }

    #[test]
    fn no_escalation_for_short_wait_no_questions() {
        let session = make_session("recent", SessionState::Waiting);
        let output = "completed the task, ready for next instructions";
        // 2 minutes, no decision patterns
        let result = should_escalate(&session, output, 120);
        assert!(result.is_none());
    }

    #[test]
    fn escalation_on_question_mark_in_output() {
        let session = make_session("asker", SessionState::Waiting);
        let output = "Do you want me to continue with the refactor?";
        let result = should_escalate(&session, output, 30);
        assert!(result.is_some());
    }
}
