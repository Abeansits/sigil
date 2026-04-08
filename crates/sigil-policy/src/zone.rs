//! Trust zone transition validation.
//!
//! The zone transition table enforces architectural boundaries:
//!
//! | From | To | Rule |
//! |------|----|------|
//! | Z0 Ingress | Z1 Control Plane | Allowed (bridge adapters) |
//! | Z1 Control Plane | Z2 Agent Runtime | Allowed (conductor to agent) |
//! | Z1 Control Plane | Z3 Host Privileged | T3+ with human confirmation |
//! | Z2 Agent Runtime | Z1 Control Plane | Allowed (agent signals back) |
//! | Z2 Agent Runtime | Z3 Host Privileged | BLOCKED |
//! | Same zone | Same zone | Always allowed |
//! | Everything else | -- | Denied |

use sigil_core::trust::{Tier, TrustZone};

use crate::error::PolicyError;

/// Validate that a zone transition is permitted for the given tier.
///
/// Returns `Ok(())` if the transition is allowed.
///
/// # Errors
///
/// - [`PolicyError::ZoneTransitionDenied`] if the transition is
///   architecturally forbidden (e.g., agent runtime to host privileged).
/// - [`PolicyError::TierCeilingExceeded`] if the transition requires a
///   higher tier than the principal holds (e.g., control plane to host
///   privileged without T3).
pub fn validate_zone_transition(
    from: TrustZone,
    to: TrustZone,
    tier: Tier,
) -> Result<(), PolicyError> {
    // Same zone is always fine.
    if from == to {
        return Ok(());
    }

    match (from, to) {
        // Z0 -> Z1: bridge adapters forward into control plane.
        // Z2 -> Z1: agents signal back to conductor (status, requests).
        // Z1 -> Z2: conductor dispatches work to agents.
        (TrustZone::Ingress | TrustZone::AgentRuntime, TrustZone::ControlPlane)
        | (TrustZone::ControlPlane, TrustZone::AgentRuntime) => Ok(()),

        // Z1 -> Z3: control plane can reach host, but only at T3+.
        (TrustZone::ControlPlane, TrustZone::HostPrivileged) => {
            if tier >= Tier::T3 {
                Ok(())
            } else {
                Err(PolicyError::TierCeilingExceeded {
                    required: Tier::T3,
                    ceiling: tier,
                })
            }
        }

        // Z2 -> Z3: BLOCKED -- agents never directly access host.
        (TrustZone::AgentRuntime, TrustZone::HostPrivileged) => {
            Err(PolicyError::ZoneTransitionDenied { from, to })
        }

        // Everything else is denied.
        _ => Err(PolicyError::ZoneTransitionDenied { from, to }),
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn same_zone_always_allowed() {
        let zones = [
            TrustZone::Ingress,
            TrustZone::ControlPlane,
            TrustZone::AgentRuntime,
            TrustZone::HostPrivileged,
        ];
        for zone in zones {
            assert!(
                validate_zone_transition(zone, zone, Tier::T0).is_ok(),
                "same-zone transition should be allowed for {zone:?}",
            );
        }
    }

    #[test]
    fn ingress_to_control_plane_allowed() {
        assert!(
            validate_zone_transition(TrustZone::Ingress, TrustZone::ControlPlane, Tier::T0,)
                .is_ok()
        );
    }

    #[test]
    fn control_plane_to_agent_runtime_allowed() {
        assert!(
            validate_zone_transition(TrustZone::ControlPlane, TrustZone::AgentRuntime, Tier::T0,)
                .is_ok()
        );
    }

    #[test]
    fn agent_runtime_to_control_plane_allowed() {
        assert!(
            validate_zone_transition(TrustZone::AgentRuntime, TrustZone::ControlPlane, Tier::T0,)
                .is_ok()
        );
    }

    #[test]
    fn control_plane_to_host_privileged_requires_t3() {
        // T2 is too low.
        assert_matches!(
            validate_zone_transition(TrustZone::ControlPlane, TrustZone::HostPrivileged, Tier::T2,),
            Err(PolicyError::TierCeilingExceeded {
                required: Tier::T3,
                ceiling: Tier::T2,
            })
        );

        // T3 is sufficient.
        assert!(
            validate_zone_transition(TrustZone::ControlPlane, TrustZone::HostPrivileged, Tier::T3,)
                .is_ok()
        );

        // T3Plus is also fine.
        assert!(
            validate_zone_transition(
                TrustZone::ControlPlane,
                TrustZone::HostPrivileged,
                Tier::T3Plus,
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_runtime_to_host_privileged_always_blocked() {
        // Even at highest tier, agents cannot reach host directly.
        assert_matches!(
            validate_zone_transition(
                TrustZone::AgentRuntime,
                TrustZone::HostPrivileged,
                Tier::T3Plus,
            ),
            Err(PolicyError::ZoneTransitionDenied {
                from: TrustZone::AgentRuntime,
                to: TrustZone::HostPrivileged,
            })
        );
    }

    #[test]
    fn ingress_to_agent_runtime_denied() {
        assert_matches!(
            validate_zone_transition(TrustZone::Ingress, TrustZone::AgentRuntime, Tier::T3Plus,),
            Err(PolicyError::ZoneTransitionDenied { .. })
        );
    }

    #[test]
    fn ingress_to_host_privileged_denied() {
        assert_matches!(
            validate_zone_transition(TrustZone::Ingress, TrustZone::HostPrivileged, Tier::T3Plus,),
            Err(PolicyError::ZoneTransitionDenied { .. })
        );
    }

    #[test]
    fn host_privileged_to_ingress_denied() {
        assert_matches!(
            validate_zone_transition(TrustZone::HostPrivileged, TrustZone::Ingress, Tier::T3Plus,),
            Err(PolicyError::ZoneTransitionDenied { .. })
        );
    }
}

#[cfg(test)]
mod proptest_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use proptest::prelude::*;
    use sigil_core::trust::{Tier, TrustZone};

    use super::*;

    fn arb_zone() -> impl Strategy<Value = TrustZone> {
        prop_oneof![
            Just(TrustZone::Ingress),
            Just(TrustZone::ControlPlane),
            Just(TrustZone::AgentRuntime),
            Just(TrustZone::HostPrivileged),
        ]
    }

    fn arb_tier() -> impl Strategy<Value = Tier> {
        prop_oneof![
            Just(Tier::T0),
            Just(Tier::T1),
            Just(Tier::T2),
            Just(Tier::T3),
            Just(Tier::T3Plus),
        ]
    }

    proptest! {
        /// Same-zone transitions are always allowed regardless of tier.
        #[test]
        fn same_zone_always_allowed(zone in arb_zone(), tier in arb_tier()) {
            prop_assert!(
                validate_zone_transition(zone, zone, tier).is_ok(),
                "same-zone {zone:?} should always be allowed at {tier:?}"
            );
        }

        /// AgentRuntime → HostPrivileged is architecturally blocked
        /// regardless of tier.
        #[test]
        fn agent_to_host_always_blocked(tier in arb_tier()) {
            let result = validate_zone_transition(
                TrustZone::AgentRuntime,
                TrustZone::HostPrivileged,
                tier,
            );
            prop_assert!(
                result.is_err(),
                "AgentRuntime→HostPrivileged should always be blocked, got Ok at {tier:?}"
            );
        }

        /// ControlPlane → HostPrivileged is allowed iff tier >= T3.
        #[test]
        fn control_plane_to_host_tier_gated(tier in arb_tier()) {
            let result = validate_zone_transition(
                TrustZone::ControlPlane,
                TrustZone::HostPrivileged,
                tier,
            );
            if tier >= Tier::T3 {
                prop_assert!(
                    result.is_ok(),
                    "ControlPlane→HostPrivileged should be allowed at {tier:?}"
                );
            } else {
                prop_assert!(
                    result.is_err(),
                    "ControlPlane→HostPrivileged should be denied at {tier:?}"
                );
            }
        }

        /// Zone transitions are deterministic: same inputs always give
        /// the same result.
        #[test]
        fn zone_transition_is_deterministic(
            from in arb_zone(),
            to in arb_zone(),
            tier in arb_tier(),
        ) {
            let r1 = validate_zone_transition(from, to, tier);
            let r2 = validate_zone_transition(from, to, tier);
            prop_assert_eq!(r1.is_ok(), r2.is_ok());
        }
    }
}
