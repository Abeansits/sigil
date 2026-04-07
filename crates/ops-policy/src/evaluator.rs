//! Core policy evaluation logic.
//!
//! The [`Evaluator`] takes an [`ActionRequest`] and produces a
//! [`PolicyDecision`] by checking principal identity, tier ceilings,
//! zone transitions, and (eventually) approval grants.

use ops_core::action::{Action, ActionRequest, PolicyDecision};
use ops_core::origin::ActionOrigin;
use ops_core::principal::resolve_principal;
use ops_core::trust::{Capability, Tier, TrustZone};

use crate::error::PolicyError;
use crate::zone::validate_zone_transition;

/// Configuration for the policy evaluator.
///
/// In production this will be loaded from a config file; for now it
/// uses the default principal resolution from `ops-core`.
#[derive(Clone, Debug, Default)]
pub struct EvaluatorConfig {
    // Future: per-user tier ceilings, allowed capability overrides, etc.
}

/// The core policy evaluator. Stateless -- all state lives in the
/// config and the grant store (when wired up).
#[derive(Clone, Debug)]
pub struct Evaluator {
    _config: EvaluatorConfig,
}

impl Evaluator {
    #[must_use]
    pub fn new(config: EvaluatorConfig) -> Self {
        Self { _config: config }
    }

    /// Evaluate an action request and return a policy decision.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ZoneTransitionDenied`] if the action
    /// crosses a zone boundary that is architecturally forbidden
    /// (e.g., agent runtime to host privileged).
    ///
    /// # Flow
    ///
    /// 1. Resolve origin to principal.
    /// 2. Check principal is active (not revoked).
    /// 3. Determine required capability and tier.
    /// 4. Check tier ceiling.
    /// 5. Validate zone transition.
    /// 6. For T3+, return `NeedsApproval` unless `HumanApproved`.
    /// 7. For T2, return `NeedsApproval` unless `HumanApproved` (grant
    ///    checking TODO).
    /// 8. Otherwise, `Allow`.
    pub fn evaluate(&self, request: &ActionRequest) -> Result<PolicyDecision, PolicyError> {
        // 1. Resolve principal.
        let principal = resolve_principal(&request.origin);

        // 2. Check active status.
        if !principal.is_active() {
            return Ok(PolicyDecision::Deny {
                reason: format!("principal '{}' is revoked", principal.identity),
            });
        }

        // 3. Required capability and tier.
        let capability = request.action.required_capability();
        let required_tier = capability.minimum_tier();
        let effective_ceiling = principal.effective_ceiling();

        // 4. Tier ceiling check.
        if required_tier > effective_ceiling {
            return Ok(PolicyDecision::Deny {
                reason: format!(
                    "tier ceiling exceeded: action requires {required_tier:?}, \
                     principal '{}' ceiling is {effective_ceiling:?}",
                    principal.identity,
                ),
            });
        }

        // 5. Zone transition.
        let origin_zone = request.origin.trust_zone();
        let target_zone = action_target_zone(&request.action);
        validate_zone_transition(origin_zone, target_zone, effective_ceiling)?;

        // 6-7. Approval logic.
        if required_tier >= Tier::T3 {
            return Ok(check_privileged_approval(request, capability));
        }

        if required_tier >= Tier::T2 {
            return Ok(check_infrastructure_approval(request, capability));
        }

        // 8. T0-T1: allowed.
        Ok(PolicyDecision::Allow)
    }
}

/// T3+ actions require human approval unless origin is `HumanApproved`.
fn check_privileged_approval(request: &ActionRequest, capability: Capability) -> PolicyDecision {
    if is_human_approved(&request.origin) {
        return PolicyDecision::Allow;
    }

    // TODO: check grant store for a valid grant that covers this
    // capability. For now, always request approval.
    tracing::info!(
        capability = ?capability,
        origin = ?request.origin,
        "T3+ action requires approval -- grant checking not yet wired"
    );

    PolicyDecision::NeedsApproval {
        description: format!("{capability:?} requires human approval (tier 3+)"),
    }
}

/// T2 actions: Sebastian auto-allowed from CLI / `HumanApproved`,
/// others need approval.
fn check_infrastructure_approval(
    request: &ActionRequest,
    capability: Capability,
) -> PolicyDecision {
    if is_human_approved(&request.origin) {
        return PolicyDecision::Allow;
    }

    // `LocalCli` resolves to Sebastian with T3Plus ceiling -- auto-allow
    // for T2 actions.
    if matches!(request.origin, ActionOrigin::LocalCli) {
        return PolicyDecision::Allow;
    }

    // TODO: check grant store. For now, request approval.
    tracing::info!(
        capability = ?capability,
        origin = ?request.origin,
        "T2 action requires approval -- grant checking not yet wired"
    );

    PolicyDecision::NeedsApproval {
        description: format!("{capability:?} requires approval (tier 2)"),
    }
}

/// Determine the target trust zone for an action.
///
/// - T3+ capabilities target `HostPrivileged` (filesystem, network,
///   process ops).
/// - Below T3 stays in `ControlPlane` (session management,
///   configuration, read-only).
fn action_target_zone(action: &Action) -> TrustZone {
    let tier = action.required_capability().minimum_tier();
    if tier >= Tier::T3 {
        TrustZone::HostPrivileged
    } else {
        TrustZone::ControlPlane
    }
}

/// Check whether the origin is `HumanApproved`.
fn is_human_approved(origin: &ActionOrigin) -> bool {
    matches!(origin, ActionOrigin::HumanApproved { .. })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use assert_matches::assert_matches;

    use ops_core::id::SessionId;

    use super::*;

    fn eval() -> Evaluator {
        Evaluator::new(EvaluatorConfig::default())
    }

    fn make_request(origin: ActionOrigin, action: Action) -> ActionRequest {
        ActionRequest::new(action, origin)
    }

    // ------------------------------------------------------------------
    // Table-driven auth tests
    // ------------------------------------------------------------------

    /// (origin, action, expected decision variant)
    #[test]
    fn table_driven_policy_decisions() {
        let evaluator = eval();

        let session_id = SessionId::new();

        struct Case {
            name: &'static str,
            origin: ActionOrigin,
            action: Action,
            check: fn(&PolicyDecision) -> bool,
        }

        let cases = [
            // -- LocalCli --
            Case {
                name: "LocalCli + ListSessions -> Allow (T0, anyone)",
                origin: ActionOrigin::LocalCli,
                action: Action::ListSessions,
                check: |d| matches!(d, PolicyDecision::Allow),
            },
            Case {
                name: "LocalCli + ReadHostFile -> NeedsApproval (T3, needs confirmation)",
                origin: ActionOrigin::LocalCli,
                action: Action::ReadHostFile {
                    path: PathBuf::from("/etc/hosts"),
                },
                check: |d| matches!(d, PolicyDecision::NeedsApproval { .. }),
            },
            Case {
                name: "LocalCli + BreakGlass -> NeedsApproval (T3+)",
                origin: ActionOrigin::LocalCli,
                action: Action::BreakGlass {
                    command: vec!["ls".into()],
                    cwd: PathBuf::from("/tmp"),
                    justification: "testing".into(),
                },
                check: |d| matches!(d, PolicyDecision::NeedsApproval { .. }),
            },
            Case {
                name: "LocalCli + CreateWorktree -> Allow (T2, Sebastian auto-allowed)",
                origin: ActionOrigin::LocalCli,
                action: Action::CreateWorktree {
                    session_id,
                    branch: "feature/test".into(),
                },
                check: |d| matches!(d, PolicyDecision::Allow),
            },
            // -- BridgeSlack (Paul) --
            Case {
                name: "BridgeSlack(Paul) + ListSessions -> Allow (T0, within T1 ceiling)",
                origin: ActionOrigin::BridgeSlack {
                    user_id: "U_PAUL".into(),
                    channel_id: "C_GEN".into(),
                },
                action: Action::ListSessions,
                check: |d| matches!(d, PolicyDecision::Allow),
            },
            Case {
                name: "BridgeSlack(Paul) + SendMessage -> Allow (T1, within ceiling)",
                origin: ActionOrigin::BridgeSlack {
                    user_id: "U_PAUL".into(),
                    channel_id: "C_GEN".into(),
                },
                action: Action::SendMessage {
                    session_id,
                    message: "hello".into(),
                },
                check: |d| matches!(d, PolicyDecision::Allow),
            },
            Case {
                name: "BridgeSlack(Paul) + ReadHostFile -> Deny (T3, exceeds T1 ceiling)",
                origin: ActionOrigin::BridgeSlack {
                    user_id: "U_PAUL".into(),
                    channel_id: "C_GEN".into(),
                },
                action: Action::ReadHostFile {
                    path: PathBuf::from("/etc/passwd"),
                },
                check: |d| matches!(d, PolicyDecision::Deny { .. }),
            },
            Case {
                name: "BridgeSlack(Paul) + BreakGlass -> Deny (T3+, exceeds ceiling)",
                origin: ActionOrigin::BridgeSlack {
                    user_id: "U_PAUL".into(),
                    channel_id: "C_GEN".into(),
                },
                action: Action::BreakGlass {
                    command: vec!["rm".into(), "-rf".into()],
                    cwd: PathBuf::from("/"),
                    justification: "chaos".into(),
                },
                check: |d| matches!(d, PolicyDecision::Deny { .. }),
            },
            // -- AgentGenerated --
            Case {
                name: "AgentGenerated + ListSessions -> Allow (T0)",
                origin: ActionOrigin::AgentGenerated { session_id },
                action: Action::ListSessions,
                check: |d| matches!(d, PolicyDecision::Allow),
            },
            Case {
                name: "AgentGenerated + ReadHostFile -> Deny (T3, exceeds agent ceiling)",
                origin: ActionOrigin::AgentGenerated { session_id },
                action: Action::ReadHostFile {
                    path: PathBuf::from("/etc/shadow"),
                },
                check: |d| matches!(d, PolicyDecision::Deny { .. }),
            },
            // -- HumanApproved wrapping BridgeSlack --
            Case {
                name: "HumanApproved(BridgeSlack) + ReadHostFile -> Allow (elevated)",
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
                check: |d| matches!(d, PolicyDecision::Allow),
            },
            // -- SystemHeartbeat --
            Case {
                name: "SystemHeartbeat + ListSessions -> Allow",
                origin: ActionOrigin::SystemHeartbeat,
                action: Action::ListSessions,
                check: |d| matches!(d, PolicyDecision::Allow),
            },
            Case {
                name: "SystemHeartbeat + ReadHostFile -> Deny",
                origin: ActionOrigin::SystemHeartbeat,
                action: Action::ReadHostFile {
                    path: PathBuf::from("/etc/passwd"),
                },
                check: |d| matches!(d, PolicyDecision::Deny { .. }),
            },
        ];

        for case in &cases {
            let request = make_request(case.origin.clone(), case.action.clone());
            let decision = evaluator
                .evaluate(&request)
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
            assert!(
                (case.check)(&decision),
                "FAILED: {}\n  got: {decision:?}",
                case.name,
            );
        }
    }

    // ------------------------------------------------------------------
    // Individual edge-case tests
    // ------------------------------------------------------------------

    #[test]
    fn agent_generated_send_message_allowed() {
        let session_id = SessionId::new();
        let request = make_request(
            ActionOrigin::AgentGenerated { session_id },
            Action::SendMessage {
                session_id,
                message: "status update".into(),
            },
        );
        let decision = eval()
            .evaluate(&request)
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        assert_matches!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn bridge_telegram_manage_session_allowed() {
        let request = make_request(
            ActionOrigin::BridgeTelegram {
                user_id: "12345".into(),
            },
            Action::StartSession {
                session_id: SessionId::new(),
            },
        );
        let decision = eval()
            .evaluate(&request)
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        // Telegram users get T3 ceiling, so T1 (ManageSession) is allowed.
        assert_matches!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn bridge_slack_modify_infrastructure_denied_by_ceiling() {
        let request = make_request(
            ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
            Action::CreateWorktree {
                session_id: SessionId::new(),
                branch: "feature/x".into(),
            },
        );
        let decision = eval()
            .evaluate(&request)
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        // Slack user is T1 ceiling, T2 (ModifyInfrastructure) exceeds it.
        assert_matches!(decision, PolicyDecision::Deny { .. });
    }

    #[test]
    fn human_approved_break_glass_allowed() {
        let request = make_request(
            ActionOrigin::HumanApproved {
                approver: "sebastian".into(),
                original_origin: Box::new(ActionOrigin::LocalCli),
            },
            Action::BreakGlass {
                command: vec!["whoami".into()],
                cwd: PathBuf::from("/tmp"),
                justification: "debugging".into(),
            },
        );
        let decision = eval()
            .evaluate(&request)
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        assert_matches!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn action_target_zone_for_read_is_control_plane() {
        assert_eq!(
            action_target_zone(&Action::ListSessions),
            TrustZone::ControlPlane,
        );
    }

    #[test]
    fn action_target_zone_for_host_file_is_privileged() {
        assert_eq!(
            action_target_zone(&Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            }),
            TrustZone::HostPrivileged,
        );
    }

    #[test]
    fn action_target_zone_for_break_glass_is_privileged() {
        assert_eq!(
            action_target_zone(&Action::BreakGlass {
                command: vec!["ls".into()],
                cwd: PathBuf::from("/tmp"),
                justification: "test".into(),
            }),
            TrustZone::HostPrivileged,
        );
    }
}
