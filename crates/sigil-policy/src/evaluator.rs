//! Core policy evaluation logic.
//!
//! The [`Evaluator`] takes an [`ActionRequest`] and produces a
//! [`PolicyDecision`] by checking principal identity, tier ceilings,
//! zone transitions, and approval grants.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use sigil_core::action::{Action, ActionRequest, ActionResult, PolicyDecision};
use sigil_core::content::SanitizationRequirement;
use sigil_core::origin::ActionOrigin;
use sigil_core::principal::{PlatformIdentity, resolve_principal};
use sigil_core::trust::{Capability, Tier, TrustZone};

use crate::error::PolicyError;
use crate::fatigue::{FatigueGuard, FatigueLevel};
use crate::grants::GrantStore;
use crate::zone::validate_zone_transition;

/// Configuration for the policy evaluator.
///
/// Per-user tier ceilings allow the bridge identity config to feed
/// into the policy engine, converging bridge and core principal
/// resolution into a single path.
#[derive(Clone, Debug, Default)]
pub struct EvaluatorConfig {
    /// Per-user tier ceiling overrides. Keyed by [`PlatformIdentity`],
    /// which is extracted from [`ActionOrigin`] via
    /// [`ActionOrigin::platform_identity()`].
    ///
    /// When present, overrides the default tier ceiling from
    /// `resolve_principal()`. This lets bridge identity config
    /// (e.g., `AllowedUser.tier_ceiling`) feed directly into
    /// policy evaluation.
    pub user_tier_ceilings: HashMap<PlatformIdentity, Tier>,

    /// Thresholds for the post-dispatch sanitization gate (see
    /// [`Evaluator::evaluate_result`]). PR6 ships the struct empty —
    /// the check is presence-and-content-type only. PR7 populates
    /// risk-score / rule-id / size-/encoding-rejection thresholds
    /// here, and the evaluator's gate reads from this field.
    pub sanitization: crate::sanitization::SanitizationConfig,
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
        // 1. Resolve principal, applying per-user tier ceiling overrides.
        let mut principal = resolve_principal(&request.origin);
        if let Some(platform_id) = request.origin.platform_identity() {
            if let Some(&ceiling) = self.config.user_tier_ceilings.get(&platform_id) {
                principal.tier_ceiling = ceiling;
            }
        }

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

        // 7b. T0/T1 capabilities that still require an explicit grant
        //     (e.g., FetchExternalContent). Tier-ceiling-passing is not
        //     sufficient — without a grant, the capability is gated
        //     through the same infrastructure-approval path as T2.
        if capability.requires_grant() {
            return Ok(self
                .check_infrastructure_approval(request, capability, &principal.identity)
                .await);
        }

        // 8. T0-T1: allowed.
        Ok(PolicyDecision::Allow)
    }

    /// Post-dispatch check: enforce the action's
    /// [`SanitizationRequirement`] against its [`ActionResult`].
    ///
    /// Call this after [`Self::evaluate`] returned `Allow` and the
    /// runtime produced a result. The check is separate because a
    /// sanitize report only exists *after* the runtime has fetched
    /// external content and run it through `sigil-content`.
    ///
    /// Failure modes:
    ///
    /// - Action declares [`SanitizationRequirement::Required`] and
    ///   the result carries no report → `Deny`.
    /// - Report is present but its `content_type` does not match the
    ///   declared type → `Deny`.
    ///
    /// Actions with [`SanitizationRequirement::None`] (every variant
    /// in the workspace today) pass through unchanged — the hot path
    /// is a single pattern match against `None`, no result inspection.
    ///
    /// # Errors
    ///
    /// Infallible in PR6 — all denial paths return `Ok(PolicyDecision::Deny)`.
    /// The signature returns `Result` so downstream checks (e.g.
    /// risk-score thresholds in PR7) can surface evaluator errors
    /// without another API break.
    #[allow(clippy::unused_async)] // Ok(...) today; PR7 may await grant-store reads
    pub async fn evaluate_result(
        &self,
        request: &ActionRequest,
        result: &ActionResult,
    ) -> Result<PolicyDecision, PolicyError> {
        // `SanitizationRequirement` is #[non_exhaustive]; fall through
        // to a fail-closed deny for any future variant so the addition
        // of a new requirement kind can't silently pass through here.
        match request.action.sanitization_requirement() {
            SanitizationRequirement::None => Ok(PolicyDecision::Allow),
            SanitizationRequirement::Required(expected_type) => {
                let Some(report) = result.sanitize_report.as_ref() else {
                    return Ok(PolicyDecision::Deny {
                        reason: format!(
                            "sanitization requirement not satisfied: \
                             missing sanitize report (expected {expected_type:?})"
                        ),
                    });
                };
                if report.content_type != expected_type {
                    return Ok(PolicyDecision::Deny {
                        reason: format!(
                            "sanitization requirement not satisfied: \
                             content-type mismatch (expected {expected_type:?}, \
                             got {:?})",
                            report.content_type,
                        ),
                    });
                }
                // PR6 is deliberately permissive past the presence /
                // content-type checks — risk-score and rule-id
                // thresholds land in PR7 alongside the conductor
                // wiring, so "has a report of the right type" is
                // good enough today.
                Ok(PolicyDecision::Allow)
            }
            other => Ok(PolicyDecision::Deny {
                reason: format!(
                    "sanitization requirement not satisfied: \
                     unknown SanitizationRequirement variant ({other:?}); \
                     evaluator needs an explicit arm"
                ),
            }),
        }
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
    #![allow(clippy::expect_used, clippy::panic)]

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

    // ------------------------------------------------------------------
    // Post-dispatch SanitizationRequirement check (PR6 of 7)
    // ------------------------------------------------------------------

    mod sanitization {
        use sigil_core::action::ActionResult;
        use sigil_core::content::{
            ContentSource, ContentType, Fingerprint, REPORT_SCHEMA_VERSION, SanitizeReport,
        };
        use sigil_core::normalize::NormalizeResult;

        use super::*;

        fn sample_report(content_type: ContentType) -> SanitizeReport {
            let key = b"policy-test-key";
            SanitizeReport {
                schema_version: REPORT_SCHEMA_VERSION,
                rule_set_version: 1,
                scoring_version: 1,
                source: ContentSource::from_url("https://example.com/page").expect("url"),
                content_type,
                bytes_in: 42,
                bytes_out: 40,
                stripped_elements: vec![],
                text_normalize: NormalizeResult::default(),
                findings: vec![],
                risk_score: 10,
                repetition_ratio: 0.0,
                size_rejected: false,
                encoding_rejected: false,
                nonce: "abc12345".into(),
                duration_ms: 2,
                raw_fingerprint: Fingerprint::compute(key, b"raw").expect("fp"),
                sanitized_fingerprint: Fingerprint::compute(key, b"clean").expect("fp"),
            }
        }

        #[tokio::test]
        async fn action_without_requirement_allows_empty_result() {
            // Every current Action variant has SanitizationRequirement::None,
            // so an empty ActionResult must be accepted unchanged — this is
            // the "no regression for pre-sanitize actions" guarantee.
            let evaluator = eval();
            let request = make_request(ActionOrigin::LocalCli, Action::ListSessions);
            let result = ActionResult::new();

            let decision = evaluator
                .evaluate_result(&request, &result)
                .await
                .expect("no infallible error today");
            assert_matches!(decision, PolicyDecision::Allow);
        }

        #[tokio::test]
        async fn action_without_requirement_allows_result_with_report() {
            // Defensive: even if a caller attaches a report to an action
            // that does not declare a requirement, that's fine — the
            // evaluator's job is to enforce "required implies present",
            // not "not-required implies absent".
            let evaluator = eval();
            let request = make_request(ActionOrigin::LocalCli, Action::ListSessions);
            let result = ActionResult::new().with_sanitize_report(sample_report(ContentType::Html));

            let decision = evaluator
                .evaluate_result(&request, &result)
                .await
                .expect("no infallible error today");
            assert_matches!(decision, PolicyDecision::Allow);
        }

        // The two "required" paths exercise the check logic directly,
        // without waiting for an Action variant that actually declares
        // a SanitizationRequirement::Required. We reproduce what the
        // check does when the requirement is Required — the hot path
        // behavior — by driving evaluate_result's logic through a
        // small helper that mirrors the decision branches.
        //
        // When the first external-content Action variant lands (PR7+),
        // these helpers become unnecessary and the tests should switch
        // to real requests.

        fn check(requirement: SanitizationRequirement, result: &ActionResult) -> PolicyDecision {
            match requirement {
                SanitizationRequirement::None => PolicyDecision::Allow,
                SanitizationRequirement::Required(expected_type) => {
                    let Some(report) = result.sanitize_report.as_ref() else {
                        return PolicyDecision::Deny {
                            reason: format!(
                                "sanitization requirement not satisfied: \
                                 missing sanitize report (expected {expected_type:?})"
                            ),
                        };
                    };
                    if report.content_type != expected_type {
                        return PolicyDecision::Deny {
                            reason: format!(
                                "sanitization requirement not satisfied: \
                                 content-type mismatch (expected {expected_type:?}, \
                                 got {:?})",
                                report.content_type,
                            ),
                        };
                    }
                    PolicyDecision::Allow
                }
                other => PolicyDecision::Deny {
                    reason: format!("unknown variant {other:?}"),
                },
            }
        }

        #[test]
        fn required_but_missing_report_denies() {
            let result = ActionResult::new();
            let decision = check(
                SanitizationRequirement::Required(ContentType::Html),
                &result,
            );
            assert_matches!(
                decision,
                PolicyDecision::Deny { reason }
                if reason.contains("missing sanitize report")
            );
        }

        #[test]
        fn required_with_matching_content_type_allows() {
            let result = ActionResult::new().with_sanitize_report(sample_report(ContentType::Html));
            let decision = check(
                SanitizationRequirement::Required(ContentType::Html),
                &result,
            );
            assert_matches!(decision, PolicyDecision::Allow);
        }

        #[test]
        fn required_with_wrong_content_type_denies() {
            let result = ActionResult::new().with_sanitize_report(sample_report(ContentType::Json));
            let decision = check(
                SanitizationRequirement::Required(ContentType::Html),
                &result,
            );
            assert_matches!(
                decision,
                PolicyDecision::Deny { reason }
                if reason.contains("content-type mismatch")
            );
        }

        #[test]
        fn denied_reason_is_audit_legible() {
            // The denial reason is what the HMAC-chained audit log
            // records; it must be specific enough that a later
            // investigator can distinguish "missing report" from
            // "wrong content type" without diffing structs.
            let missing = check(
                SanitizationRequirement::Required(ContentType::Html),
                &ActionResult::new(),
            );
            let mismatched = check(
                SanitizationRequirement::Required(ContentType::Html),
                &ActionResult::new().with_sanitize_report(sample_report(ContentType::Json)),
            );

            match (missing, mismatched) {
                (PolicyDecision::Deny { reason: a }, PolicyDecision::Deny { reason: b }) => {
                    assert!(a.contains("missing"), "missing-report reason: {a}");
                    assert!(b.contains("mismatch"), "mismatch reason: {b}");
                    assert_ne!(a, b);
                }
                other => panic!("expected two Deny decisions, got {other:?}"),
            }
        }
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

#[cfg(test)]
mod proptest_tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use std::path::PathBuf;
    use std::sync::Arc;

    use proptest::prelude::*;

    use sigil_core::action::{Action, ActionRequest, PolicyDecision};
    use sigil_core::id::SessionId;
    use sigil_core::origin::ActionOrigin;
    use sigil_core::principal::resolve_principal;
    use sigil_core::trust::Tier;

    use crate::grants::NoopGrantStore;

    use super::*;

    fn fresh_eval() -> Evaluator<NoopGrantStore> {
        Evaluator::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore))
    }

    /// Compare two `PolicyDecision` values for equality (the type
    /// doesn't derive `PartialEq`).
    fn decisions_equal(a: &PolicyDecision, b: &PolicyDecision) -> bool {
        match (a, b) {
            (PolicyDecision::Allow, PolicyDecision::Allow) => true,
            (PolicyDecision::Deny { reason: r1 }, PolicyDecision::Deny { reason: r2 }) => r1 == r2,
            (
                PolicyDecision::NeedsApproval { description: d1 },
                PolicyDecision::NeedsApproval { description: d2 },
            ) => d1 == d2,
            _ => false,
        }
    }

    // ── Origin strategies ─────────────────────────────────────────

    fn arb_origin() -> impl Strategy<Value = ActionOrigin> {
        prop_oneof![
            Just(ActionOrigin::LocalCli),
            "[0-9]{1,10}".prop_map(|user_id| ActionOrigin::BridgeTelegram { user_id }),
            ("[A-Z0-9]{1,10}", "[A-Z0-9]{1,10}").prop_map(|(user_id, channel_id)| {
                ActionOrigin::BridgeSlack {
                    user_id,
                    channel_id,
                }
            }),
            Just(()).prop_map(|()| ActionOrigin::AgentGenerated {
                session_id: SessionId::new(),
            }),
            Just(ActionOrigin::SystemHeartbeat),
        ]
    }

    /// Origins that resolve to low-ceiling principals (≤ T1).
    fn arb_low_ceiling_origin() -> impl Strategy<Value = ActionOrigin> {
        prop_oneof![
            ("[A-Z0-9]{1,10}", "[A-Z0-9]{1,10}").prop_map(|(uid, cid)| {
                ActionOrigin::BridgeSlack {
                    user_id: uid,
                    channel_id: cid,
                }
            }),
            Just(()).prop_map(|()| ActionOrigin::AgentGenerated {
                session_id: SessionId::new(),
            }),
            Just(ActionOrigin::SystemHeartbeat),
        ]
    }

    // ── Action strategies by tier ─────────────────────────────────

    fn arb_t0_action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::ListSessions),
            Just(Action::ListGroups),
            Just(Action::GetSystemStatus),
        ]
    }

    fn arb_t3_action() -> impl Strategy<Value = Action> {
        "[a-z]{1,10}".prop_map(|s| Action::ReadHostFile {
            path: PathBuf::from(format!("/tmp/{s}")),
        })
    }

    fn arb_t3plus_action() -> impl Strategy<Value = Action> {
        "[a-z]{1,10}".prop_map(|s| Action::BreakGlass {
            command: vec!["echo".into(), s],
            cwd: PathBuf::from("/tmp"),
            justification: "proptest".into(),
        })
    }

    proptest! {
        /// Evaluating the same request on two fresh evaluators (identical
        /// initial state) always produces the same decision.
        ///
        /// Uses T0 actions to avoid fatigue guard state interactions.
        #[test]
        fn policy_is_deterministic(
            origin in arb_origin(),
            action in arb_t0_action(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let eval1 = fresh_eval();
                let eval2 = fresh_eval();
                let request = ActionRequest::new(action, origin);

                let d1 = eval1.evaluate(&request).await
                    .unwrap_or_else(|e| PolicyDecision::Deny { reason: e.to_string() });
                let d2 = eval2.evaluate(&request).await
                    .unwrap_or_else(|e| PolicyDecision::Deny { reason: e.to_string() });

                prop_assert!(
                    decisions_equal(&d1, &d2),
                    "non-deterministic: {d1:?} vs {d2:?}"
                );
                Ok(())
            })?;
        }

        /// If a principal's tier ceiling is below the required tier,
        /// the policy always denies (regardless of other factors).
        ///
        /// Low-ceiling origins (Slack T1, Agent T1, Heartbeat T1) paired
        /// with T3 actions must always result in Deny.
        #[test]
        fn tier_ceiling_enforces_deny(
            origin in arb_low_ceiling_origin(),
            action in arb_t3_action(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let evaluator = fresh_eval();
                let request = ActionRequest::new(action, origin);
                let decision = evaluator.evaluate(&request).await
                    .unwrap_or_else(|e| PolicyDecision::Deny { reason: e.to_string() });

                prop_assert!(
                    matches!(decision, PolicyDecision::Deny { .. }),
                    "expected Deny for low-ceiling origin + T3 action, got {decision:?}"
                );
                Ok(())
            })?;
        }

        /// AgentGenerated origin + T3+ action always results in Deny
        /// because the agent's T1 ceiling is below T3+.
        #[test]
        fn agent_generated_t3plus_always_denied(action in arb_t3plus_action()) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let evaluator = fresh_eval();
                let origin = ActionOrigin::AgentGenerated {
                    session_id: SessionId::new(),
                };
                let request = ActionRequest::new(action, origin);
                let decision = evaluator.evaluate(&request).await
                    .unwrap_or_else(|e| PolicyDecision::Deny { reason: e.to_string() });

                prop_assert!(
                    matches!(decision, PolicyDecision::Deny { .. }),
                    "agent + T3+ should always be denied, got {decision:?}"
                );
                Ok(())
            })?;
        }

        /// For any origin, T0 read actions are always allowed (every
        /// principal has at least T0 ceiling when active).
        #[test]
        fn t0_actions_always_allowed(
            origin in arb_origin(),
            action in arb_t0_action(),
        ) {
            let principal = resolve_principal(&origin);
            // Only test active principals (not Revoked).
            prop_assume!(principal.is_active());
            prop_assume!(principal.effective_ceiling() >= Tier::T0);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let evaluator = fresh_eval();
                let request = ActionRequest::new(action, origin);
                let decision = evaluator.evaluate(&request).await
                    .unwrap_or_else(|e| PolicyDecision::Deny { reason: e.to_string() });

                prop_assert!(
                    matches!(decision, PolicyDecision::Allow),
                    "T0 action should always be allowed for active principal, got {decision:?}"
                );
                Ok(())
            })?;
        }
    }
}
