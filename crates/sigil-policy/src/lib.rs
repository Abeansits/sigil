//! sigil-policy -- Security policy evaluation engine.
//!
//! This crate is the security brain of sigil. It evaluates whether
//! an [`ActionRequest`] should be allowed, denied, or requires human
//! approval, based on:
//!
//! - **Trust zones**: Z0 (Ingress) through Z3 (`HostPrivileged`), with
//!   validated transitions.
//! - **Tier ceilings**: Each principal has a maximum tier; actions
//!   requiring a higher tier are denied.
//! - **Approval grants**: Time-limited, use-limited tokens that elevate
//!   permissions for specific capabilities.
//! - **Input normalization**: Strip invisible Unicode characters and
//!   detect homoglyph attacks before processing.
//!
//! # Architecture
//!
//! The public entry point is [`PolicyService`], which implements the
//! [`sigil_core::PolicyEngine`] trait. Internally it delegates to the
//! [`evaluator::Evaluator`] for the actual decision logic, including
//! approval grant lookups via the [`GrantStore`] trait.

pub mod error;
pub mod evaluator;
pub mod fatigue;
pub mod grants;
pub mod normalize;
pub mod paths;
pub mod sanitization;
pub mod zone;

pub use error::PolicyError;
pub use evaluator::{Evaluator, EvaluatorConfig};
pub use fatigue::{FatigueGuard, FatigueLevel};
pub use grants::{ApprovalGrant, GrantStore, NoopGrantStore};
pub use normalize::{NormalizeResult, normalize_text, strip_ansi};
pub use paths::{quick_path_check, validate_path};
pub use sanitization::SanitizationConfig;

use std::fmt;
use std::sync::Arc;

use sigil_core::action::{ActionRequest, PolicyDecision};
use sigil_core::error::CoreError;

/// The policy service — implements [`sigil_core::PolicyEngine`].
///
/// Wraps an [`Evaluator`] and adds tracing around decisions.
/// Generic over `G: GrantStore` for approval grant lookups.
pub struct PolicyService<G> {
    evaluator: Evaluator<G>,
}

// Manual Clone: delegates to Evaluator<G>'s Clone impl (no bounds on G).
impl<G> Clone for PolicyService<G> {
    fn clone(&self) -> Self {
        Self {
            evaluator: self.evaluator.clone(),
        }
    }
}

// Manual Debug: delegates to Evaluator<G>'s Debug impl (no bounds on G).
impl<G> fmt::Debug for PolicyService<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyService")
            .field("evaluator", &self.evaluator)
            .finish()
    }
}

impl<G: GrantStore> PolicyService<G> {
    #[must_use]
    pub fn new(config: EvaluatorConfig, grants: Arc<G>) -> Self {
        Self {
            evaluator: Evaluator::new(config, grants),
        }
    }
}

impl<G: GrantStore> sigil_core::PolicyEngine for PolicyService<G> {
    async fn evaluate(&self, request: &ActionRequest) -> Result<PolicyDecision, CoreError> {
        let decision = self.evaluator.evaluate(request).await.map_err(|e| {
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
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use sigil_core::PolicyEngine;
    use sigil_core::action::Action;
    use sigil_core::origin::ActionOrigin;

    use super::*;

    fn service() -> PolicyService<NoopGrantStore> {
        PolicyService::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore))
    }

    #[tokio::test]
    async fn policy_service_implements_trait() {
        let service = service();
        let request = ActionRequest::new(Action::ListSessions, ActionOrigin::LocalCli);
        let decision = service.evaluate(&request).await.expect("should succeed");
        assert!(matches!(decision, PolicyDecision::Allow));
    }

    #[tokio::test]
    async fn policy_service_deny_logs_reason() {
        let service = service();
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
