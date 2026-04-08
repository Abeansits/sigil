//! Core policy evaluation logic.
//!
//! The [`Evaluator`] takes an [`ActionRequest`] and produces a
//! [`PolicyDecision`] by checking principal identity, tier ceilings,
//! zone transitions, and approval grants.

use std::fmt;
use std::sync::{Arc, Mutex};

use sigil_core::action::{Action, ActionRequest, PolicyDecision};
use sigil_core::origin::ActionOrigin;
use sigil_core::principal::resolve_principal;
use sigil_core::trust::{Capability, Tier, TrustZone};

use crate::error::PolicyError;
use crate::fatigue::{FatigueGuard, FatigueLevel};
use crate::grants::GrantStore;
use crate::zone::validate_zone_transition;

/// Configuration for the policy evaluator.
///
/// In production this will be loaded from a config file; for now it
/// uses the default principal resolution from `sigil-core`.
#[derive(Clone, Debug, Default)]
pub struct EvaluatorConfig {
    // Future: per-user tier ceilings, allowed capability overrides, etc.
}

/// The core policy evaluator. Delegates to a [`GrantStore`] for
/// approval grant lookups.
///
/// Generic over `G: GrantStore` because the `GrantStore` trait uses
/// RPITIT (`impl Future` returns) and is not dyn-compatible.
pub struct Evaluator<G> {
    config: EvaluatorConfig,
    grants: Arc<G>,
    fatigue: Arc<Mutex<FatigueGuard>>,
}

// Manual Clone: Arc<G> is always Clone regardless of G.
impl<G> Clone for Evaluator<G> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            grants: Arc::clone(&self.grants),
            fatigue: Arc::clone(&self.fatigue),
        }
    }
}

// Manual Debug: skip the grants field (no Debug bound on G needed).
impl<G> fmt::Debug for Evaluator<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Evaluator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<G: GrantStore> Evaluator<G> {
    #[must_use]
    pub fn new(config: EvaluatorConfig, grants: Arc<G>) -> Self {
        Self {
            config,
            grants,
            fatigue: Arc::new(Mutex::new(FatigueGuard::default())),
        }
    }

    /// Create an evaluator with a custom fatigue guard (for testing).
    #[must_use]
    pub fn with_fatigue(config: EvaluatorConfig, grants: Arc<G>, fatigue: FatigueGuard) -> Self {
        Self {
            config,
            grants,
            fatigue: Arc::new(Mutex::new(fatigue)),
        }
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
    /// 6. For T3+, check grant store, then return `NeedsApproval`
    ///    unless `HumanApproved` or a valid grant exists.
    /// 7. For T2, same grant-aware logic (Sebastian auto-allowed
    ///    from CLI).
    /// 8. Otherwise, `Allow`.
    pub async fn evaluate(&self, request: &ActionRequest) -> Result<PolicyDecision, PolicyError> {
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

        // 6-7. Approval logic with fatigue guard and grant checking.
        if required_tier >= Tier::T2 {
            // Check fatigue before processing any approval-tier action.
            if let Some(deny) = self.check_fatigue() {
                return Ok(deny);
            }
        }

        if required_tier >= Tier::T3 {
            return Ok(self
                .check_privileged_approval(request, capability, &principal.identity)
                .await);
        }

        if required_tier >= Tier::T2 {
            return Ok(self
                .check_infrastructure_approval(request, capability, &principal.identity)
                .await);
        }

        // 8. T0-T1: allowed.
        Ok(PolicyDecision::Allow)
    }

    /// T3+ actions require human approval unless origin is `HumanApproved`
    /// or a valid approval grant exists.
    async fn check_privileged_approval(
        &self,
        request: &ActionRequest,
        capability: Capability,
        principal_id: &str,
    ) -> PolicyDecision {
        if is_human_approved(&request.origin) {
            return PolicyDecision::Allow;
        }

        // Check the grant store for a valid grant covering this action.
        if self
            .try_consume_grant(principal_id, capability, &request.action)
            .await
        {
            tracing::info!(
                capability = ?capability,
                principal = principal_id,
                "T3+ action allowed via approval grant"
            );
            return PolicyDecision::Allow;
        }

        PolicyDecision::NeedsApproval {
            description: format!("{capability:?} requires human approval (tier 3+)"),
        }
    }

    /// T2 actions: Sebastian auto-allowed from CLI / `HumanApproved`,
    /// others need a grant or explicit approval.
    async fn check_infrastructure_approval(
        &self,
        request: &ActionRequest,
        capability: Capability,
        principal_id: &str,
    ) -> PolicyDecision {
        if is_human_approved(&request.origin) {
            return PolicyDecision::Allow;
        }

        // `LocalCli` resolves to Sebastian with T3Plus ceiling — auto-allow
        // for T2 actions.
        if matches!(request.origin, ActionOrigin::LocalCli) {
            return PolicyDecision::Allow;
        }

        // Check the grant store.
        if self
            .try_consume_grant(principal_id, capability, &request.action)
            .await
        {
            tracing::info!(
                capability = ?capability,
                principal = principal_id,
                "T2 action allowed via approval grant"
            );
            return PolicyDecision::Allow;
        }

        PolicyDecision::NeedsApproval {
            description: format!("{capability:?} requires approval (tier 2)"),
        }
    }

    /// Check fatigue guard: enforce cooldown and record the request.
    /// Returns `Some(Deny)` if the request should be blocked.
    fn check_fatigue(&self) -> Option<PolicyDecision> {
        let mut guard = self
            .fatigue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Enforce cooldown from a prior high-risk detection.
        if let Err(e) = guard.check_cooldown() {
            tracing::warn!("fatigue cooldown active: {e}");
            return Some(PolicyDecision::Deny {
                reason: e.to_string(),
            });
        }

        // Record this request and check the resulting fatigue level.
        let level = guard.record_request();
        if level == FatigueLevel::HighRisk {
            tracing::warn!("fatigue high-risk threshold reached — denying approval");
            return Some(PolicyDecision::Deny {
                reason: "approval fatigue: too many approval requests in a short window".to_owned(),
            });
        }

        None
    }

    /// Look up a matching grant, consume it if found, and persist the
    /// updated use count. Returns `true` if a valid grant was consumed.
    async fn try_consume_grant(
        &self,
        principal_id: &str,
        capability: Capability,
        action: &Action,
    ) -> bool {
        let resource = action.resource_scope();
        let grant = self
            .grants
            .find_grant(principal_id, capability, resource.as_deref())
            .await;

        match grant {
            Ok(Some(mut grant)) if grant.is_valid() => {
                grant.consume();
                // Fail closed: if we can't persist the consumed grant,
                // deny the action to prevent double-spend.
                if let Err(e) = self.grants.save_grant(&grant).await {
                    tracing::error!(
                        grant_id = %grant.id,
                        error = %e,
                        "failed to persist consumed grant — denying action (fail closed)"
                    );
                    return false;
                }
                true
            }
            // No valid grant found (or grant invalid — shouldn't happen
            // if store filters correctly, but be defensive).
            Ok(_) => false,
            Err(e) => {
                tracing::warn!(
                    principal = principal_id,
                    capability = ?capability,
                    error = %e,
                    "grant store lookup failed — falling through to NeedsApproval"
                );
                false
            }
        }
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
    #![allow(clippy::expect_used)]

    use std::path::PathBuf;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use tokio::sync::Mutex;

    use sigil_core::id::SessionId;
    use sigil_core::trust::Capability;

    use crate::error::PolicyError;
    use crate::grants::{ApprovalGrant, GrantStore, NoopGrantStore};

    use super::*;

    fn eval() -> Evaluator<NoopGrantStore> {
        Evaluator::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore))
    }

    fn make_request(origin: ActionOrigin, action: Action) -> ActionRequest {
        ActionRequest::new(action, origin)
    }

    // ------------------------------------------------------------------
    // Mock grant store for testing grant-aware evaluation
    // ------------------------------------------------------------------

    /// A test grant store that returns a preconfigured grant.
    #[derive(Debug)]
    struct MockGrantStore {
        grant: Mutex<Option<ApprovalGrant>>,
    }

    impl MockGrantStore {
        fn with_grant(grant: ApprovalGrant) -> Self {
            Self {
                grant: Mutex::new(Some(grant)),
            }
        }

        fn empty() -> Self {
            Self {
                grant: Mutex::new(None),
            }
        }
    }

    impl GrantStore for MockGrantStore {
        async fn find_grant(
            &self,
            principal: &str,
            capability: Capability,
            resource: Option<&str>,
        ) -> Result<Option<ApprovalGrant>, PolicyError> {
            let guard = self.grant.lock().await;
            if let Some(ref grant) = *guard {
                if grant.matches(principal, capability, resource) && grant.is_valid() {
                    return Ok(Some(grant.clone()));
                }
            }
            Ok(None)
        }

        async fn save_grant(&self, grant: &ApprovalGrant) -> Result<(), PolicyError> {
            let mut guard = self.grant.lock().await;
            *guard = Some(grant.clone());
            Ok(())
        }
    }

    fn make_grant(
        principal: &str,
        capability: Capability,
        resource_scope: Option<&str>,
        ttl_secs: i64,
        max_uses: Option<u32>,
    ) -> ApprovalGrant {
        let now = time::OffsetDateTime::now_utc();
        ApprovalGrant {
            id: sigil_core::id::RequestId::new(),
            principal_id: principal.into(),
            capability,
            resource_scope: resource_scope.map(Into::into),
            expires_at: now + time::Duration::seconds(ttl_secs),
            max_uses,
            uses: 0,
            issued_by: "sebastian".into(),
            issued_at: now,
        }
    }

    fn eval_with_grant(grant: ApprovalGrant) -> Evaluator<MockGrantStore> {
        Evaluator::new(
            EvaluatorConfig::default(),
            Arc::new(MockGrantStore::with_grant(grant)),
        )
    }

    fn eval_with_empty_store() -> Evaluator<MockGrantStore> {
        Evaluator::new(
            EvaluatorConfig::default(),
            Arc::new(MockGrantStore::empty()),
        )
    }

    // ------------------------------------------------------------------
    // Table-driven auth tests
    // ------------------------------------------------------------------

    /// (origin, action, expected decision variant)
    #[tokio::test]
    #[allow(clippy::too_many_lines, clippy::items_after_statements)]
    async fn table_driven_policy_decisions() {
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
            let decision =
                evaluator
                    .evaluate(&request)
                    .await
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

    #[tokio::test]
    async fn agent_generated_send_message_allowed() {
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
            .await
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        assert_matches!(decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn bridge_telegram_manage_session_allowed() {
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
            .await
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        // Telegram users get T3 ceiling, so T1 (ManageSession) is allowed.
        assert_matches!(decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn bridge_slack_modify_infrastructure_denied_by_ceiling() {
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
            .await
            .unwrap_or_else(|e| PolicyDecision::Deny {
                reason: e.to_string(),
            });
        // Slack user is T1 ceiling, T2 (ModifyInfrastructure) exceeds it.
        assert_matches!(decision, PolicyDecision::Deny { .. });
    }

    #[tokio::test]
    async fn human_approved_break_glass_allowed() {
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
            .await
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

    // ------------------------------------------------------------------
    // Grant-aware evaluation tests
    // ------------------------------------------------------------------

    // Grant tests use LocalCli origin (ControlPlane zone, principal "sebastian")
    // because Ingress -> HostPrivileged zone transitions are blocked before
    // grant checking. LocalCli resolves to "sebastian" principal.

    #[tokio::test]
    async fn grant_found_allows_t3_action() {
        // LocalCli (ControlPlane, T3Plus ceiling) requesting ReadHostFile
        // with a valid grant — should be allowed via grant.
        let grant = make_grant(
            "sebastian",
            Capability::ReadHostFile,
            Some("/etc/hosts"),
            300,
            Some(5),
        );
        let evaluator = eval_with_grant(grant);
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn expired_grant_returns_needs_approval() {
        // Grant with -1s TTL = already expired.
        let grant = make_grant(
            "sebastian",
            Capability::ReadHostFile,
            Some("/etc/hosts"),
            -1,
            Some(5),
        );
        let evaluator = eval_with_grant(grant);
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::NeedsApproval { .. });
    }

    #[tokio::test]
    async fn grant_wrong_scope_returns_needs_approval() {
        // Grant for /home/paul but request for /etc/shadow.
        let grant = make_grant(
            "sebastian",
            Capability::ReadHostFile,
            Some("/home/paul"),
            300,
            Some(5),
        );
        let evaluator = eval_with_grant(grant);
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::ReadHostFile {
                path: PathBuf::from("/etc/shadow"),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::NeedsApproval { .. });
    }

    #[tokio::test]
    async fn no_grant_in_store_returns_needs_approval() {
        let evaluator = eval_with_empty_store();
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::NeedsApproval { .. });
    }

    #[tokio::test]
    async fn grant_consumed_increments_use_count() {
        let grant = make_grant(
            "sebastian",
            Capability::ReadHostFile,
            Some("/etc/hosts"),
            300,
            Some(3),
        );
        let store = Arc::new(MockGrantStore::with_grant(grant));
        let evaluator = Evaluator::new(EvaluatorConfig::default(), Arc::clone(&store));

        let request = make_request(
            ActionOrigin::LocalCli,
            Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
        );

        // First use — should be allowed and use count incremented.
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::Allow);

        // Verify use count was incremented in the store.
        let stored = store.grant.lock().await;
        let g = stored.as_ref().expect("grant should exist");
        assert_eq!(g.uses, 1);
    }

    #[tokio::test]
    async fn grant_wrong_capability_returns_needs_approval() {
        // Grant for WriteHostFile but request is ReadHostFile.
        let grant = make_grant("sebastian", Capability::WriteHostFile, None, 300, Some(5));
        let evaluator = eval_with_grant(grant);
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::NeedsApproval { .. });
    }

    // ------------------------------------------------------------------
    // Fatigue guard integration tests
    // ------------------------------------------------------------------

    use crate::fatigue::FatigueGuard;

    fn eval_with_fatigue(fatigue: FatigueGuard) -> Evaluator<NoopGrantStore> {
        Evaluator::with_fatigue(
            EvaluatorConfig::default(),
            Arc::new(NoopGrantStore),
            fatigue,
        )
    }

    #[tokio::test]
    async fn fatigue_normal_allows_t2_action() {
        // Fresh fatigue guard — should allow T2 actions normally.
        let evaluator = eval_with_fatigue(FatigueGuard::new(10, 300));
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::CreateWorktree {
                session_id: SessionId::new(),
                branch: "feature/test".into(),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn fatigue_high_risk_denies_t3_action() {
        // Pre-load fatigue guard past threshold so the next request
        // triggers HighRisk.
        let mut fatigue = FatigueGuard::new(3, 300);
        for _ in 0..3 {
            fatigue.record_request();
        }
        // The next record_request() (count=4 > threshold=3) will be HighRisk.
        let evaluator = eval_with_fatigue(fatigue);
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::ReadHostFile {
                path: PathBuf::from("/etc/hosts"),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::Deny { reason } if reason.contains("fatigue"));
    }

    #[tokio::test]
    async fn fatigue_cooldown_denies_t2_action() {
        // Push past threshold to trigger HighRisk and set cooldown.
        let mut fatigue = FatigueGuard::new(2, 300);
        for _ in 0..3 {
            fatigue.record_request();
        }
        // Cooldown is now active (last_high_risk is set).
        // Create a fresh guard that has a cooldown set but the deque
        // is below threshold (simulating time passing for the window
        // but not for the cooldown).
        // Instead, we just reuse the guard as-is — check_cooldown fires
        // before record_request, so it will deny immediately.
        let evaluator = eval_with_fatigue(fatigue);
        let request = make_request(
            ActionOrigin::LocalCli,
            Action::CreateWorktree {
                session_id: SessionId::new(),
                branch: "feature/test".into(),
            },
        );
        let decision =
            evaluator
                .evaluate(&request)
                .await
                .unwrap_or_else(|e| PolicyDecision::Deny {
                    reason: e.to_string(),
                });
        assert_matches!(decision, PolicyDecision::Deny { reason } if reason.contains("cooldown"));
    }
}
