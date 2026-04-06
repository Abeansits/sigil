//! End-to-end policy evaluation: ActionRequest -> PolicyService -> decision.
//!
//! These tests exercise the full chain across ops-core and ops-policy,
//! verifying that the trust model works as designed.

use std::path::PathBuf;

use assert_matches::assert_matches;

use ops_core::action::{Action, ActionRequest, PolicyDecision};
use ops_core::id::SessionId;
use ops_core::origin::ActionOrigin;
use ops_core::PolicyEngine;
use ops_policy::{EvaluatorConfig, PolicyService};

fn service() -> PolicyService {
    PolicyService::new(EvaluatorConfig::default())
}

// ------------------------------------------------------------------
// Paul (Slack, T1 ceiling) scenarios
// ------------------------------------------------------------------

#[tokio::test]
async fn paul_slack_list_sessions_is_allowed() {
    let request = ActionRequest::new(
        Action::ListSessions,
        ActionOrigin::BridgeSlack {
            user_id: "U_PAUL".into(),
            channel_id: "C_GEN".into(),
        },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Allow);
}

#[tokio::test]
async fn paul_slack_send_message_is_allowed() {
    let request = ActionRequest::new(
        Action::SendMessage {
            session_id: SessionId::new(),
            message: "check status".into(),
        },
        ActionOrigin::BridgeSlack {
            user_id: "U_PAUL".into(),
            channel_id: "C_GEN".into(),
        },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Allow);
}

#[tokio::test]
async fn paul_slack_read_host_file_is_denied() {
    let request = ActionRequest::new(
        Action::ReadHostFile {
            path: PathBuf::from("/etc/passwd"),
        },
        ActionOrigin::BridgeSlack {
            user_id: "U_PAUL".into(),
            channel_id: "C_GEN".into(),
        },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Deny { reason } => {
        assert!(
            reason.contains("ceiling"),
            "deny reason should mention ceiling: {reason}"
        );
    });
}

#[tokio::test]
async fn paul_slack_break_glass_is_denied() {
    let request = ActionRequest::new(
        Action::BreakGlass {
            command: vec!["rm".into(), "-rf".into()],
            cwd: PathBuf::from("/"),
            justification: "chaos".into(),
        },
        ActionOrigin::BridgeSlack {
            user_id: "U_PAUL".into(),
            channel_id: "C_GEN".into(),
        },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Deny { .. });
}

#[tokio::test]
async fn paul_slack_modify_infrastructure_is_denied() {
    let request = ActionRequest::new(
        Action::CreateWorktree {
            session_id: SessionId::new(),
            branch: "feature/test".into(),
        },
        ActionOrigin::BridgeSlack {
            user_id: "U_PAUL".into(),
            channel_id: "C_GEN".into(),
        },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    // T2 action exceeds Paul's T1 ceiling.
    assert_matches!(decision, PolicyDecision::Deny { .. });
}

// ------------------------------------------------------------------
// Sebastian (LocalCli, T3Plus ceiling) scenarios
// ------------------------------------------------------------------

#[tokio::test]
async fn local_cli_list_sessions_is_allowed() {
    let request = ActionRequest::new(Action::ListSessions, ActionOrigin::LocalCli);

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Allow);
}

#[tokio::test]
async fn local_cli_create_worktree_is_allowed() {
    // Sebastian from CLI doing T2 action -- auto-allowed.
    let request = ActionRequest::new(
        Action::CreateWorktree {
            session_id: SessionId::new(),
            branch: "feature/infra".into(),
        },
        ActionOrigin::LocalCli,
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Allow);
}

#[tokio::test]
async fn local_cli_break_glass_needs_approval() {
    let request = ActionRequest::new(
        Action::BreakGlass {
            command: vec!["whoami".into()],
            cwd: PathBuf::from("/tmp"),
            justification: "debugging".into(),
        },
        ActionOrigin::LocalCli,
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::NeedsApproval { description } => {
        assert!(
            description.contains("approval"),
            "should mention approval: {description}"
        );
    });
}

#[tokio::test]
async fn local_cli_read_host_file_needs_approval() {
    let request = ActionRequest::new(
        Action::ReadHostFile {
            path: PathBuf::from("/etc/hosts"),
        },
        ActionOrigin::LocalCli,
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    // T3 action from CLI still requires confirmation.
    assert_matches!(decision, PolicyDecision::NeedsApproval { .. });
}

// ------------------------------------------------------------------
// HumanApproved elevation scenarios
// ------------------------------------------------------------------

#[tokio::test]
async fn human_approved_elevates_slack_origin_for_read_host_file() {
    let request = ActionRequest::new(
        Action::ReadHostFile {
            path: PathBuf::from("/etc/hosts"),
        },
        ActionOrigin::HumanApproved {
            approver: "sebastian".into(),
            original_origin: Box::new(ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            }),
        },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    // HumanApproved elevates to ControlPlane (T3Plus ceiling).
    assert_matches!(decision, PolicyDecision::Allow);
}

#[tokio::test]
async fn human_approved_elevates_for_break_glass() {
    let request = ActionRequest::new(
        Action::BreakGlass {
            command: vec!["whoami".into()],
            cwd: PathBuf::from("/tmp"),
            justification: "debugging".into(),
        },
        ActionOrigin::HumanApproved {
            approver: "sebastian".into(),
            original_origin: Box::new(ActionOrigin::LocalCli),
        },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Allow);
}

// ------------------------------------------------------------------
// Agent-generated scenarios
// ------------------------------------------------------------------

#[tokio::test]
async fn agent_generated_list_sessions_is_allowed() {
    let session_id = SessionId::new();
    let request = ActionRequest::new(
        Action::ListSessions,
        ActionOrigin::AgentGenerated { session_id },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Allow);
}

#[tokio::test]
async fn agent_generated_read_host_file_is_denied() {
    let session_id = SessionId::new();
    let request = ActionRequest::new(
        Action::ReadHostFile {
            path: PathBuf::from("/etc/shadow"),
        },
        ActionOrigin::AgentGenerated { session_id },
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    // Agents have T1 ceiling -- T3 action is denied.
    assert_matches!(decision, PolicyDecision::Deny { .. });
}

// ------------------------------------------------------------------
// SystemHeartbeat scenarios
// ------------------------------------------------------------------

#[tokio::test]
async fn system_heartbeat_read_only_is_allowed() {
    let request = ActionRequest::new(Action::GetSystemStatus, ActionOrigin::SystemHeartbeat);

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    assert_matches!(decision, PolicyDecision::Allow);
}

#[tokio::test]
async fn system_heartbeat_read_host_file_is_denied() {
    let request = ActionRequest::new(
        Action::ReadHostFile {
            path: PathBuf::from("/etc/passwd"),
        },
        ActionOrigin::SystemHeartbeat,
    );

    let decision = service()
        .evaluate(&request)
        .await
        .expect("evaluation should succeed");

    // Heartbeat principal has T1 ceiling -- T3 is denied.
    assert_matches!(decision, PolicyDecision::Deny { .. });
}
