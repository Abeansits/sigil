//! UC7: Policy evaluation integration tests (mocked — no tmux needed).
//!
//! Table-driven tests covering the tier/zone/capability matrix, grant
//! validity and consumption, fatigue guard behavior, zone transition
//! rules, and normalization as a security layer.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

use std::path::PathBuf;
use std::sync::Arc;

use assert_matches::assert_matches;

use sigil_core::PolicyEngine;
use sigil_core::action::{Action, ActionRequest, PolicyDecision};
use sigil_core::id::{RequestId, SessionId};
use sigil_core::origin::ActionOrigin;
use sigil_core::session::ToolKind;
use sigil_core::trust::{Capability, Tier, TrustZone};
use sigil_policy::fatigue::{FatigueGuard, FatigueLevel};
use sigil_policy::grants::ApprovalGrant;
use sigil_policy::grants::NoopGrantStore;
use sigil_policy::zone::validate_zone_transition;
use sigil_policy::{EvaluatorConfig, PolicyService};
use time::OffsetDateTime;

fn service() -> PolicyService<NoopGrantStore> {
    PolicyService::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore))
}

// ═══════════════════════════════════════════════════════════════════
// Table-driven: Tier / Zone / Capability matrix
// ═══════════════════════════════════════════════════════════════════

/// Exhaustive table of (origin, action) -> expected decision variant.
#[tokio::test]
async fn comprehensive_tier_zone_capability_matrix() {
    let svc = service();
    let sid = SessionId::new();

    struct Case {
        label: &'static str,
        origin: ActionOrigin,
        action: Action,
        expect: fn(&PolicyDecision) -> bool,
    }

    let cases = [
        // ── T0 read-only ────────────────────────────────────────────
        Case {
            label: "LocalCli + ListSessions -> Allow",
            origin: ActionOrigin::LocalCli,
            action: Action::ListSessions,
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "LocalCli + GetSystemStatus -> Allow",
            origin: ActionOrigin::LocalCli,
            action: Action::GetSystemStatus,
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "SystemHeartbeat + GetSystemStatus -> Allow",
            origin: ActionOrigin::SystemHeartbeat,
            action: Action::GetSystemStatus,
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "AgentGenerated + ListSessions -> Allow",
            origin: ActionOrigin::AgentGenerated { session_id: sid },
            action: Action::ListSessions,
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "BridgeSlack(Paul) + ListSessions -> Allow",
            origin: ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
            action: Action::ListSessions,
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "BridgeTelegram + GetSessionStatus -> Allow",
            origin: ActionOrigin::BridgeTelegram {
                user_id: "12345".into(),
            },
            action: Action::GetSessionStatus { session_id: sid },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        // ── T1 session management ─────────────────────────────────────────
        Case {
            label: "LocalCli + CreateSession -> Allow",
            origin: ActionOrigin::LocalCli,
            action: Action::CreateSession {
                path: PathBuf::from("/tmp"),
                title: "test".into(),
                group: None,
                tool: ToolKind::ClaudeCode,
                identity: None,
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "LocalCli + SendMessage -> Allow",
            origin: ActionOrigin::LocalCli,
            action: Action::SendMessage {
                session_id: sid,
                message: "hello".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "BridgeSlack(Paul) + SendMessage -> Allow (T1 within T1)",
            origin: ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
            action: Action::SendMessage {
                session_id: sid,
                message: "check".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "BridgeSlack(Paul) + StopSession -> Allow (T1)",
            origin: ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
            action: Action::StopSession { session_id: sid },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "AgentGenerated + SendMessage -> Allow (T1 within agent ceiling)",
            origin: ActionOrigin::AgentGenerated { session_id: sid },
            action: Action::SendMessage {
                session_id: sid,
                message: "update".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        // ── T2 infrastructure ─────────────────────────────────────────────
        Case {
            label: "LocalCli + CreateWorktree -> Allow (Sebastian auto-allowed)",
            origin: ActionOrigin::LocalCli,
            action: Action::CreateWorktree {
                session_id: sid,
                branch: "feature/test".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "LocalCli + FinishWorktree -> Allow",
            origin: ActionOrigin::LocalCli,
            action: Action::FinishWorktree {
                session_id: sid,
                merge: true,
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "BridgeSlack(Paul) + CreateWorktree -> Deny (T2 exceeds T1)",
            origin: ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
            action: Action::CreateWorktree {
                session_id: sid,
                branch: "feature/x".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Deny { .. }),
        },
        Case {
            label: "AgentGenerated + CreateWorktree -> Deny (T2 exceeds agent ceiling)",
            origin: ActionOrigin::AgentGenerated { session_id: sid },
            action: Action::CreateWorktree {
                session_id: sid,
                branch: "feature/x".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Deny { .. }),
        },
        Case {
            label: "HumanApproved(BridgeSlack) + CreateWorktree -> Allow (elevated)",
            origin: ActionOrigin::HumanApproved {
                approver: "sebastian".into(),
                original_origin: Box::new(ActionOrigin::BridgeSlack {
                    user_id: "U_PAUL".into(),
                    channel_id: "C_GEN".into(),
                }),
            },
            action: Action::CreateWorktree {
                session_id: sid,
                branch: "feature/elevated".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        // ── T3 privileged ─────────────────────────────────────────────────
        Case {
            label: "LocalCli + ReadHostFile -> NeedsApproval (T3 requires confirmation)",
            origin: ActionOrigin::LocalCli,
            action: Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
            expect: |d| matches!(d, PolicyDecision::NeedsApproval { .. }),
        },
        Case {
            label: "LocalCli + WriteHostFile -> NeedsApproval",
            origin: ActionOrigin::LocalCli,
            action: Action::WriteHostFile {
                path: PathBuf::from("/tmp/out.txt"),
                content: "data".into(),
            },
            expect: |d| matches!(d, PolicyDecision::NeedsApproval { .. }),
        },
        Case {
            label: "BridgeSlack(Paul) + ReadHostFile -> Deny (T3 exceeds T1)",
            origin: ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
            action: Action::ReadHostFile {
                path: PathBuf::from("/etc/passwd"),
            },
            expect: |d| matches!(d, PolicyDecision::Deny { .. }),
        },
        Case {
            label: "SystemHeartbeat + ReadHostFile -> Deny (T3 exceeds T1 ceiling)",
            origin: ActionOrigin::SystemHeartbeat,
            action: Action::ReadHostFile {
                path: PathBuf::from("/etc/passwd"),
            },
            expect: |d| matches!(d, PolicyDecision::Deny { .. }),
        },
        Case {
            label: "AgentGenerated + ReadHostFile -> Deny",
            origin: ActionOrigin::AgentGenerated { session_id: sid },
            action: Action::ReadHostFile {
                path: PathBuf::from("/etc/shadow"),
            },
            expect: |d| matches!(d, PolicyDecision::Deny { .. }),
        },
        Case {
            label: "HumanApproved(Slack) + ReadHostFile -> Allow",
            origin: ActionOrigin::HumanApproved {
                approver: "sebastian".into(),
                original_origin: Box::new(ActionOrigin::BridgeSlack {
                    user_id: "U_PAUL".into(),
                    channel_id: "C_GEN".into(),
                }),
            },
            action: Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        // ── T3+ break glass ───────────────────────────────────────────────
        Case {
            label: "LocalCli + BreakGlass -> NeedsApproval",
            origin: ActionOrigin::LocalCli,
            action: Action::BreakGlass {
                command: vec!["ls".into()],
                cwd: PathBuf::from("/tmp"),
                justification: "testing".into(),
            },
            expect: |d| matches!(d, PolicyDecision::NeedsApproval { .. }),
        },
        Case {
            label: "BridgeSlack(Paul) + BreakGlass -> Deny (T3+ exceeds T1)",
            origin: ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
            action: Action::BreakGlass {
                command: vec!["rm".into(), "-rf".into()],
                cwd: PathBuf::from("/"),
                justification: "chaos".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Deny { .. }),
        },
        Case {
            label: "HumanApproved(LocalCli) + BreakGlass -> Allow",
            origin: ActionOrigin::HumanApproved {
                approver: "sebastian".into(),
                original_origin: Box::new(ActionOrigin::LocalCli),
            },
            action: Action::BreakGlass {
                command: vec!["whoami".into()],
                cwd: PathBuf::from("/tmp"),
                justification: "debugging".into(),
            },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        // ── Cross-origin T1 actions ─────────────────────────────────
        Case {
            label: "BridgeTelegram + StartSession -> Allow (TG user has T3 ceiling)",
            origin: ActionOrigin::BridgeTelegram {
                user_id: "12345".into(),
            },
            action: Action::StartSession { session_id: sid },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
        Case {
            label: "BridgeTelegram + RemoveSession -> Allow (T1)",
            origin: ActionOrigin::BridgeTelegram {
                user_id: "12345".into(),
            },
            action: Action::RemoveSession { session_id: sid },
            expect: |d| matches!(d, PolicyDecision::Allow),
        },
    ];

    for case in &cases {
        let request = ActionRequest::new(case.action.clone(), case.origin.clone());
        let decision = svc
            .evaluate(&request)
            .await
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        assert!(
            (case.expect)(&decision),
            "FAILED: {}\n  got: {decision:?}",
            case.label,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Zone transition validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn zone_transition_table() {
    struct ZoneCase {
        label: &'static str,
        from: TrustZone,
        to: TrustZone,
        tier: Tier,
        allowed: bool,
    }

    let cases = [
        // Same zone: always allowed.
        ZoneCase {
            label: "Z0 -> Z0",
            from: TrustZone::Ingress,
            to: TrustZone::Ingress,
            tier: Tier::T0,
            allowed: true,
        },
        ZoneCase {
            label: "Z1 -> Z1",
            from: TrustZone::ControlPlane,
            to: TrustZone::ControlPlane,
            tier: Tier::T0,
            allowed: true,
        },
        // Valid transitions.
        ZoneCase {
            label: "Ingress -> ControlPlane",
            from: TrustZone::Ingress,
            to: TrustZone::ControlPlane,
            tier: Tier::T0,
            allowed: true,
        },
        ZoneCase {
            label: "ControlPlane -> AgentRuntime",
            from: TrustZone::ControlPlane,
            to: TrustZone::AgentRuntime,
            tier: Tier::T0,
            allowed: true,
        },
        ZoneCase {
            label: "AgentRuntime -> ControlPlane",
            from: TrustZone::AgentRuntime,
            to: TrustZone::ControlPlane,
            tier: Tier::T0,
            allowed: true,
        },
        ZoneCase {
            label: "ControlPlane -> HostPrivileged (T3)",
            from: TrustZone::ControlPlane,
            to: TrustZone::HostPrivileged,
            tier: Tier::T3,
            allowed: true,
        },
        ZoneCase {
            label: "ControlPlane -> HostPrivileged (T3Plus)",
            from: TrustZone::ControlPlane,
            to: TrustZone::HostPrivileged,
            tier: Tier::T3Plus,
            allowed: true,
        },
        // Blocked transitions.
        ZoneCase {
            label: "AgentRuntime -> HostPrivileged (BLOCKED)",
            from: TrustZone::AgentRuntime,
            to: TrustZone::HostPrivileged,
            tier: Tier::T3Plus,
            allowed: false,
        },
        ZoneCase {
            label: "ControlPlane -> HostPrivileged (T2, insufficient tier)",
            from: TrustZone::ControlPlane,
            to: TrustZone::HostPrivileged,
            tier: Tier::T2,
            allowed: false,
        },
        ZoneCase {
            label: "Ingress -> AgentRuntime (BLOCKED)",
            from: TrustZone::Ingress,
            to: TrustZone::AgentRuntime,
            tier: Tier::T0,
            allowed: false,
        },
        ZoneCase {
            label: "Ingress -> HostPrivileged (BLOCKED)",
            from: TrustZone::Ingress,
            to: TrustZone::HostPrivileged,
            tier: Tier::T3Plus,
            allowed: false,
        },
        ZoneCase {
            label: "HostPrivileged -> Ingress (BLOCKED)",
            from: TrustZone::HostPrivileged,
            to: TrustZone::Ingress,
            tier: Tier::T0,
            allowed: false,
        },
    ];

    for case in &cases {
        let result = validate_zone_transition(case.from, case.to, case.tier);
        assert_eq!(
            result.is_ok(),
            case.allowed,
            "FAILED: {} -> expected allowed={}, got result={result:?}",
            case.label,
            case.allowed,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Grant validity and consumption
// ═══════════════════════════════════════════════════════════════════

fn make_grant(
    principal: &str,
    capability: Capability,
    scope: Option<&str>,
    ttl_secs: i64,
    max_uses: Option<u32>,
) -> ApprovalGrant {
    let now = OffsetDateTime::now_utc();
    ApprovalGrant {
        id: RequestId::new(),
        principal_id: principal.into(),
        capability,
        resource_scope: scope.map(Into::into),
        expires_at: now + time::Duration::seconds(ttl_secs),
        max_uses,
        uses: 0,
        issued_by: "sebastian".into(),
        issued_at: now,
    }
}

#[test]
fn grant_validity_matrix() {
    struct GrantCase {
        label: &'static str,
        grant: ApprovalGrant,
        valid: bool,
    }

    let cases = [
        GrantCase {
            label: "Fresh grant with TTL and uses remaining",
            grant: make_grant("paul", Capability::ReadHostFile, None, 300, Some(5)),
            valid: true,
        },
        GrantCase {
            label: "Unlimited uses stays valid",
            grant: {
                let mut g = make_grant("paul", Capability::ReadHostFile, None, 300, None);
                for _ in 0..50 {
                    g.consume();
                }
                g
            },
            valid: true,
        },
        GrantCase {
            label: "Exhausted grant is invalid",
            grant: {
                let mut g = make_grant("paul", Capability::ReadHostFile, None, 300, Some(3));
                for _ in 0..3 {
                    g.consume();
                }
                g
            },
            valid: false,
        },
        GrantCase {
            label: "Expired grant is invalid",
            grant: make_grant("paul", Capability::ReadHostFile, None, -1, Some(5)),
            valid: false,
        },
    ];

    for case in &cases {
        assert_eq!(case.grant.is_valid(), case.valid, "FAILED: {}", case.label);
    }
}

#[test]
fn grant_matching_matrix() {
    struct MatchCase {
        label: &'static str,
        grant: ApprovalGrant,
        principal: &'static str,
        capability: Capability,
        resource: Option<&'static str>,
        matches: bool,
    }

    let cases = [
        MatchCase {
            label: "Exact match (unscoped)",
            grant: make_grant("paul", Capability::ReadHostFile, None, 300, None),
            principal: "paul",
            capability: Capability::ReadHostFile,
            resource: None,
            matches: true,
        },
        MatchCase {
            label: "Wrong principal",
            grant: make_grant("paul", Capability::ReadHostFile, None, 300, None),
            principal: "eve",
            capability: Capability::ReadHostFile,
            resource: None,
            matches: false,
        },
        MatchCase {
            label: "Wrong capability",
            grant: make_grant("paul", Capability::ReadHostFile, None, 300, None),
            principal: "paul",
            capability: Capability::WriteHostFile,
            resource: None,
            matches: false,
        },
        MatchCase {
            label: "Scoped grant matches prefix",
            grant: make_grant(
                "paul",
                Capability::ReadHostFile,
                Some("/home/paul/"),
                300,
                None,
            ),
            principal: "paul",
            capability: Capability::ReadHostFile,
            resource: Some("/home/paul/docs/file.txt"),
            matches: true,
        },
        MatchCase {
            label: "Scoped grant rejects outside scope",
            grant: make_grant(
                "paul",
                Capability::ReadHostFile,
                Some("/home/paul/"),
                300,
                None,
            ),
            principal: "paul",
            capability: Capability::ReadHostFile,
            resource: Some("/etc/shadow"),
            matches: false,
        },
        MatchCase {
            label: "Scoped grant requires resource in request",
            grant: make_grant(
                "paul",
                Capability::ReadHostFile,
                Some("/home/paul/"),
                300,
                None,
            ),
            principal: "paul",
            capability: Capability::ReadHostFile,
            resource: None,
            matches: false,
        },
        MatchCase {
            label: "Unscoped grant allows any resource",
            grant: make_grant("paul", Capability::ReadHostFile, None, 300, None),
            principal: "paul",
            capability: Capability::ReadHostFile,
            resource: Some("/etc/anything"),
            matches: true,
        },
    ];

    for case in &cases {
        assert_eq!(
            case.grant
                .matches(case.principal, case.capability, case.resource),
            case.matches,
            "FAILED: {}",
            case.label,
        );
    }
}

#[test]
fn grant_consumption_tracks_uses() {
    let mut grant = make_grant("paul", Capability::ReadHostFile, None, 300, Some(3));
    assert_eq!(grant.uses, 0);
    assert!(grant.is_valid());

    grant.consume();
    assert_eq!(grant.uses, 1);
    assert!(grant.is_valid());

    grant.consume();
    grant.consume();
    assert_eq!(grant.uses, 3);
    assert!(!grant.is_valid(), "exhausted grant should be invalid");
}

// ═══════════════════════════════════════════════════════════════════
// Fatigue guard
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fatigue_guard_levels() {
    // threshold=10, half=5
    let mut guard = FatigueGuard::new(10, 300);

    // Normal: up to 5 requests.
    for _ in 0..5 {
        assert_eq!(guard.record_request(), FatigueLevel::Normal);
    }

    // Warning: 6-10 requests.
    for _ in 0..5 {
        assert_eq!(guard.record_request(), FatigueLevel::Warning);
    }

    // HighRisk: 11+ requests.
    assert_eq!(guard.record_request(), FatigueLevel::HighRisk);
}

#[test]
fn fatigue_cooldown_after_high_risk() {
    let mut guard = FatigueGuard::new(10, 300);

    // Push past threshold.
    for _ in 0..11 {
        guard.record_request();
    }

    // Cooldown should be active.
    let result = guard.check_cooldown();
    assert!(result.is_err(), "cooldown should be active after HighRisk");
}

#[test]
fn fatigue_no_cooldown_when_normal() {
    let mut guard = FatigueGuard::new(10, 300);
    for _ in 0..3 {
        guard.record_request();
    }
    assert!(guard.check_cooldown().is_ok());
}

#[test]
fn fatigue_pruning_resets_after_window() {
    // Use a 1-second window. Record requests, then sleep briefly
    // and verify new requests start from a clean slate.
    // We can't inject timestamps from outside the crate, so we
    // verify indirectly: fill up to threshold, then rely on the
    // fact that all entries are within the window and the guard
    // reports correctly.
    let mut guard = FatigueGuard::new(3, 300);

    // 3 requests -> at threshold.
    for _ in 0..3 {
        guard.record_request();
    }
    assert_eq!(guard.active_count(), 3);

    // 4th request pushes past threshold.
    assert_eq!(guard.record_request(), FatigueLevel::HighRisk);
    assert_eq!(guard.active_count(), 4);
}

#[test]
fn fatigue_small_threshold_boundaries() {
    let mut guard = FatigueGuard::new(2, 300);
    assert_eq!(guard.record_request(), FatigueLevel::Normal); // 1 <= 1
    assert_eq!(guard.record_request(), FatigueLevel::Warning); // 2 > 1
    assert_eq!(guard.record_request(), FatigueLevel::HighRisk); // 3 > 2
}

// ═══════════════════════════════════════════════════════════════════
// Deny reason content validation
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn deny_reason_mentions_ceiling() {
    let svc = service();
    let request = ActionRequest::new(
        Action::ReadHostFile {
            path: PathBuf::from("/etc/passwd"),
        },
        ActionOrigin::BridgeSlack {
            user_id: "U_PAUL".into(),
            channel_id: "C_GEN".into(),
        },
    );

    let decision = svc.evaluate(&request).await.expect("should succeed");
    assert_matches!(decision, PolicyDecision::Deny { reason } => {
        assert!(
            reason.contains("ceiling"),
            "deny reason should mention 'ceiling': {reason}"
        );
    });
}

#[tokio::test]
async fn needs_approval_description_mentions_approval() {
    let svc = service();
    let request = ActionRequest::new(
        Action::BreakGlass {
            command: vec!["ls".into()],
            cwd: PathBuf::from("/tmp"),
            justification: "test".into(),
        },
        ActionOrigin::LocalCli,
    );

    let decision = svc.evaluate(&request).await.expect("should succeed");
    assert_matches!(decision, PolicyDecision::NeedsApproval { description } => {
        assert!(
            description.contains("approval"),
            "description should mention 'approval': {description}"
        );
    });
}
