use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::origin::ActionOrigin;
use crate::trust::Tier;

/// How the principal authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthStrength {
    /// Local CLI — implicit trust (you're on the machine).
    LocalSession,
    /// Telegram — user ID verified by Telegram servers.
    PlatformVerified,
    /// Slack — workspace-scoped user ID.
    WorkspaceScoped,
    /// Agent — identified by session ID, no human authentication.
    AgentIdentity,
    /// System — internal heartbeat, no human behind it.
    SystemInternal,
}

/// Binding to a specific platform context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PlatformBinding {
    /// No platform binding (local CLI).
    None,
    /// Bound to a Telegram user.
    Telegram { user_id: String },
    /// Bound to a Slack workspace + user.
    Slack {
        workspace_id: String,
        user_id: String,
    },
    /// Bound to an agent session.
    AgentSession { session_id: crate::id::SessionId },
}

/// Current trust posture of the principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TrustPosture {
    /// Fully trusted. Normal operation.
    Trusted,
    /// Reduced trust due to anomalies (rate limiting, unusual patterns).
    Degraded,
    /// Revoked. All actions denied.
    Revoked,
}

/// A resolved identity with permissions. The policy engine maps
/// `ActionOrigin` → `Principal` → permissions.
///
/// This indirection allows the same origin to have different trust
/// postures over time (e.g., degraded after anomaly detection).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Principal {
    /// Human-readable identity (e.g., "sebastian", "paul", "agent:bookmark-extractor").
    pub identity: String,
    /// How this principal authenticated.
    pub auth_strength: AuthStrength,
    /// Platform-specific binding for anti-spoofing.
    pub platform_binding: PlatformBinding,
    /// Maximum tier this principal can reach.
    pub tier_ceiling: Tier,
    /// Current trust posture (can be degraded by anomaly detection).
    pub trust_posture: TrustPosture,
    /// When this principal was last verified.
    #[serde(with = "time::serde::rfc3339")]
    pub last_verified: OffsetDateTime,
}

impl Principal {
    /// Whether this principal's actions should be allowed (not revoked).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.trust_posture != TrustPosture::Revoked
    }

    /// The effective tier ceiling, accounting for trust posture.
    #[must_use]
    pub fn effective_ceiling(&self) -> Tier {
        match self.trust_posture {
            TrustPosture::Trusted => self.tier_ceiling,
            TrustPosture::Degraded => {
                // Degraded principals are capped at T0 (read-only)
                if self.tier_ceiling > Tier::T0 {
                    Tier::T0
                } else {
                    self.tier_ceiling
                }
            }
            TrustPosture::Revoked => Tier::T0, // Will be denied anyway
        }
    }
}

/// Resolve an `ActionOrigin` to a `Principal`.
///
/// In production, this reads from a config table mapping platform IDs
/// to known principals. This function provides the default mapping
/// that the config can override.
#[must_use]
pub fn resolve_principal(origin: &ActionOrigin) -> Principal {
    match origin {
        ActionOrigin::LocalCli => Principal {
            identity: "sebastian".into(),
            auth_strength: AuthStrength::LocalSession,
            platform_binding: PlatformBinding::None,
            tier_ceiling: Tier::T3Plus,
            trust_posture: TrustPosture::Trusted,
            last_verified: OffsetDateTime::now_utc(),
        },
        ActionOrigin::BridgeTelegram { user_id } => Principal {
            identity: format!("telegram:{user_id}"),
            auth_strength: AuthStrength::PlatformVerified,
            platform_binding: PlatformBinding::Telegram {
                user_id: user_id.clone(),
            },
            tier_ceiling: Tier::T3, // No T3+ via bridge
            trust_posture: TrustPosture::Trusted,
            last_verified: OffsetDateTime::now_utc(),
        },
        ActionOrigin::BridgeSlack {
            user_id,
            channel_id: _,
        } => Principal {
            identity: format!("slack:{user_id}"),
            auth_strength: AuthStrength::WorkspaceScoped,
            platform_binding: PlatformBinding::Slack {
                workspace_id: String::new(), // Resolved from config
                user_id: user_id.clone(),
            },
            tier_ceiling: Tier::T1, // Default for Slack users (Paul)
            trust_posture: TrustPosture::Trusted,
            last_verified: OffsetDateTime::now_utc(),
        },
        ActionOrigin::AgentGenerated { session_id } => Principal {
            identity: format!("agent:{session_id}"),
            auth_strength: AuthStrength::AgentIdentity,
            platform_binding: PlatformBinding::AgentSession {
                session_id: *session_id,
            },
            tier_ceiling: Tier::T1, // Agents request, conductor evaluates
            trust_posture: TrustPosture::Trusted,
            last_verified: OffsetDateTime::now_utc(),
        },
        ActionOrigin::SystemHeartbeat => Principal {
            identity: "system:heartbeat".into(),
            auth_strength: AuthStrength::SystemInternal,
            platform_binding: PlatformBinding::None,
            tier_ceiling: Tier::T1, // T0 + predefined T1
            trust_posture: TrustPosture::Trusted,
            last_verified: OffsetDateTime::now_utc(),
        },
        ActionOrigin::HumanApproved {
            approver,
            original_origin: _,
        } => Principal {
            identity: approver.clone(),
            auth_strength: AuthStrength::LocalSession,
            platform_binding: PlatformBinding::None,
            tier_ceiling: Tier::T3Plus,
            trust_posture: TrustPosture::Trusted,
            last_verified: OffsetDateTime::now_utc(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_cli_gets_full_access() {
        let p = resolve_principal(&ActionOrigin::LocalCli);
        assert_eq!(p.tier_ceiling, Tier::T3Plus);
        assert!(p.is_active());
    }

    #[test]
    fn slack_user_is_capped_at_t1() {
        let p = resolve_principal(&ActionOrigin::BridgeSlack {
            user_id: "U_PAUL".into(),
            channel_id: "C_GEN".into(),
        });
        assert_eq!(p.tier_ceiling, Tier::T1);
    }

    #[test]
    fn degraded_principal_drops_to_t0() {
        let mut p = resolve_principal(&ActionOrigin::LocalCli);
        assert_eq!(p.effective_ceiling(), Tier::T3Plus);
        p.trust_posture = TrustPosture::Degraded;
        assert_eq!(p.effective_ceiling(), Tier::T0);
    }

    #[test]
    fn revoked_principal_is_inactive() {
        let mut p = resolve_principal(&ActionOrigin::LocalCli);
        p.trust_posture = TrustPosture::Revoked;
        assert!(!p.is_active());
    }
}
