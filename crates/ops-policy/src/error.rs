//! Policy-specific error types.

use ops_core::trust::{Tier, TrustZone};

/// Errors that can occur during policy evaluation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    #[error("action denied: {reason}")]
    Denied { reason: String },

    #[error("zone transition not allowed: {from:?} -> {to:?}")]
    ZoneTransitionDenied { from: TrustZone, to: TrustZone },

    #[error("tier ceiling exceeded: required {required:?}, ceiling {ceiling:?}")]
    TierCeilingExceeded { required: Tier, ceiling: Tier },

    #[error("grant expired")]
    GrantExpired,

    #[error("path traversal denied: {reason}")]
    PathTraversalDenied { reason: String },

    #[error("approval fatigue cooldown active: try again after {cooldown_remaining_secs}s")]
    FatigueCooldown { cooldown_remaining_secs: i64 },

    #[error("audit error: {0}")]
    Audit(#[from] ops_audit::AuditError),
}

impl From<PolicyError> for ops_core::CoreError {
    fn from(err: PolicyError) -> Self {
        match err {
            PolicyError::Denied { reason } | PolicyError::PathTraversalDenied { reason } => {
                Self::ActionDenied { reason }
            }
            PolicyError::TierCeilingExceeded { required, ceiling } => Self::ActionDenied {
                reason: format!(
                    "tier ceiling exceeded: required {required:?}, ceiling {ceiling:?}"
                ),
            },
            PolicyError::ZoneTransitionDenied { from, to } => Self::ActionDenied {
                reason: format!("zone transition not allowed: {from:?} -> {to:?}"),
            },
            PolicyError::GrantExpired => Self::ActionDenied {
                reason: "grant expired".into(),
            },
            PolicyError::FatigueCooldown {
                cooldown_remaining_secs,
            } => Self::ActionDenied {
                reason: format!(
                    "approval fatigue cooldown active: try again after {cooldown_remaining_secs}s"
                ),
            },
            PolicyError::Audit(e) => Self::Audit {
                message: e.to_string(),
            },
        }
    }
}
