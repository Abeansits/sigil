//! ops-policy -- Security policy evaluation engine.
//!
//! This crate is the security brain of agent-ops. It evaluates whether
//! an [`ActionRequest`] should be allowed, denied, or requires human
//! approval, based on:
//!
//! - **Trust zones**: Z0 (Ingress) through Z3 (`HostPrivileged`), with
//!   validated transitions.
//! - **Tier ceilings**: Each principal has a maximum tier; actions
//!   requiring a higher tier are denied.
//! - **Approval grants**: Time-limited, use-limited tokens that elevate
//!   permissions for specific capabilities (grant store integration
//!   pending).
//! - **Input normalization**: Strip invisible Unicode characters and
//!   detect homoglyph attacks before processing.
//!
//! # Architecture
//!
//! The public entry point is [`PolicyService`], which implements the
//! [`ops_core::PolicyEngine`] trait. Internally it delegates to the
//! [`evaluator::Evaluator`] for the actual decision logic.

pub mod error;
pub mod evaluator;
pub mod fatigue;
pub mod grants;
pub mod normalize;
pub mod paths;
pub mod zone;

pub use error::PolicyError;
pub use evaluator::{Evaluator, EvaluatorConfig};
pub use fatigue::{FatigueGuard, FatigueLevel};
pub use grants::{ApprovalGrant, GrantStore};
pub use normalize::{NormalizeResult, normalize_text, strip_ansi};
pub use paths::{quick_path_check, validate_path};

use ops_core::action::{ActionRequest, PolicyDecision};
use ops_core::error::CoreError;

/// The policy service — implements [`ops_core::PolicyEngine`].
///
/// Wraps an [`Evaluator`] and adds tracing around decisions.
#[derive(Clone, Debug)]
pub struct PolicyService {
    evaluator: Evaluator,
}

impl PolicyService {
    #[must_use]
    pub fn new(config: EvaluatorConfig) -> Self {
        Self {
            evaluator: Evaluator::new(config),
        }
    }
}

impl ops_core::PolicyEngine for PolicyService {
    async fn evaluate(&self, request: &ActionRequest) -> Result<PolicyDecision, CoreError> {
        let decision = self.evaluator.evaluate(request).map_err(|e| {
            tracing::warn!(
                request_id = %request.id,
                error = %e,
                "policy evaluation failed"
            );
            CoreError::from(e)
        })?;

        match &decision {
            PolicyDecision::Allow => {
                tracing::debug!(
                    request_id = %request.id,
                    action = ?request.action,
                    origin = ?request.origin,
                    "policy: ALLOW"
                );
            }
            PolicyDecision::Deny { reason } => {
                tracing::info!(
                    request_id = %request.id,
                    action = ?request.action,
                    origin = ?request.origin,
                    reason,
                    "policy: DENY"
                );
            }
            PolicyDecision::NeedsApproval { description } => {
                tracing::info!(
                    request_id = %request.id,
                    action = ?request.action,
                    origin = ?request.origin,
                    description,
                    "policy: NEEDS_APPROVAL"
                );
            }
        }

        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use ops_core::PolicyEngine;
    use ops_core::action::Action;
    use ops_core::origin::ActionOrigin;

    use super::*;

    #[tokio::test]
    async fn policy_service_implements_trait() {
        let service = PolicyService::new(EvaluatorConfig::default());
        let request = ActionRequest::new(Action::ListSessions, ActionOrigin::LocalCli);
        let decision = service.evaluate(&request).await.expect("should succeed");
        assert!(matches!(decision, PolicyDecision::Allow));
    }

    #[tokio::test]
    async fn policy_service_deny_logs_reason() {
        let service = PolicyService::new(EvaluatorConfig::default());
        let request = ActionRequest::new(
            Action::ReadHostFile {
                path: std::path::PathBuf::from("/etc/shadow"),
            },
            ActionOrigin::BridgeSlack {
                user_id: "U_PAUL".into(),
                channel_id: "C_GEN".into(),
            },
        );
        let decision = service.evaluate(&request).await.expect("should succeed");
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }
}
