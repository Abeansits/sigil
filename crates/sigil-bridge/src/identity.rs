//! Sender allowlist and identity resolution.
//!
//! Every inbound message must pass through identity resolution before
//! processing. Only known platform IDs are accepted — unknown senders
//! are rejected at the bridge boundary.

use sigil_core::origin::ActionOrigin;
use sigil_core::trust::Tier;

use crate::error::BridgeError;

/// Configuration mapping platform user IDs to known identities.
#[derive(Clone, Debug)]
pub struct IdentityConfig {
    pub allowed_telegram_ids: Vec<AllowedUser>,
    pub allowed_slack_ids: Vec<AllowedUser>,
}

/// A known user on a specific platform.
#[derive(Clone, Debug)]
pub struct AllowedUser {
    pub platform_id: String,
    pub display_name: String,
    pub tier_ceiling: Tier,
}

/// Resolve an `ActionOrigin` to a known user in the allowlist.
///
/// Returns the matched `AllowedUser` or `BridgeError::UnknownSender`
/// if the platform user ID is not in the config.
///
/// # Errors
///
/// Returns `BridgeError::UnknownSender` if the origin's platform user
/// ID is not in the allowlist, or if the origin is not a bridge type.
pub fn resolve_identity(
    config: &IdentityConfig,
    origin: &ActionOrigin,
) -> Result<AllowedUser, BridgeError> {
    match origin {
        ActionOrigin::BridgeTelegram { user_id } => config
            .allowed_telegram_ids
            .iter()
            .find(|u| u.platform_id == *user_id)
            .cloned()
            .ok_or_else(|| BridgeError::UnknownSender {
                platform: "telegram".into(),
                user_id: user_id.clone(),
            }),

        ActionOrigin::BridgeSlack {
            user_id,
            channel_id: _,
        } => config
            .allowed_slack_ids
            .iter()
            .find(|u| u.platform_id == *user_id)
            .cloned()
            .ok_or_else(|| BridgeError::UnknownSender {
                platform: "slack".into(),
                user_id: user_id.clone(),
            }),

        ActionOrigin::LocalCli
        | ActionOrigin::AgentGenerated { .. }
        | ActionOrigin::SystemHeartbeat
        | ActionOrigin::HumanApproved { .. }
        | _ => Err(BridgeError::UnknownSender {
            platform: format!("{origin:?}"),
            user_id: String::new(),
        }),
    }
}

/// Build identity config from environment variables with hardcoded fallbacks.
///
/// Env vars (comma-separated `id:name:tier` triples):
///   - `SIGIL_TELEGRAM_USERS` — e.g. `7279215778:Sebastian:T3`
///   - `SIGIL_SLACK_USERS` — e.g. `U123:Sebastian:T3,U456:Paul:T1`
///
/// Falls back to compiled defaults if env vars are absent.
#[must_use]
pub fn default_config() -> IdentityConfig {
    let telegram_ids = parse_users_env("SIGIL_TELEGRAM_USERS").unwrap_or_else(|| {
        vec![AllowedUser {
            platform_id: "7279215778".into(),
            display_name: "Sebastian".into(),
            tier_ceiling: Tier::T3,
        }]
    });

    let slack_ids = parse_users_env("SIGIL_SLACK_USERS").unwrap_or_else(|| {
        vec![
            AllowedUser {
                platform_id: "SEBASTIAN_SLACK_ID".into(),
                display_name: "Sebastian".into(),
                tier_ceiling: Tier::T3,
            },
            AllowedUser {
                platform_id: "PAUL_SLACK_ID".into(),
                display_name: "Paul".into(),
                tier_ceiling: Tier::T1,
            },
        ]
    });

    IdentityConfig {
        allowed_telegram_ids: telegram_ids,
        allowed_slack_ids: slack_ids,
    }
}

/// Parse a comma-separated list of `id:name:tier` triples from an env var.
///
/// Returns `None` if the env var is absent. Skips malformed entries.
fn parse_users_env(var: &str) -> Option<Vec<AllowedUser>> {
    let val = std::env::var(var).ok()?;
    let users = val
        .split(',')
        .filter_map(|entry| {
            let mut parts = entry.trim().splitn(3, ':');
            let platform_id = parts.next()?.to_owned();
            let display_name = parts.next()?.to_owned();
            let tier_str = parts.next()?;
            let tier = match tier_str.to_uppercase().as_str() {
                "T0" => Tier::T0,
                "T2" => Tier::T2,
                "T3" => Tier::T3,
                // T1 is the default for any unrecognized tier
                _ => Tier::T1,
            };
            Some(AllowedUser {
                platform_id,
                display_name,
                tier_ceiling: tier,
            })
        })
        .collect::<Vec<_>>();
    if users.is_empty() { None } else { Some(users) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn known_telegram_sender_resolves_correctly() {
        let config = default_config();
        let origin = ActionOrigin::BridgeTelegram {
            user_id: "7279215778".into(),
        };
        let user = resolve_identity(&config, &origin).expect("should resolve");
        assert_eq!(user.display_name, "Sebastian");
        assert_eq!(user.tier_ceiling, Tier::T3);
    }

    #[test]
    fn unknown_telegram_sender_returns_error() {
        let config = default_config();
        let origin = ActionOrigin::BridgeTelegram {
            user_id: "UNKNOWN_ID".into(),
        };
        let err = resolve_identity(&config, &origin).expect_err("should fail");
        assert!(matches!(err, BridgeError::UnknownSender { .. }));
    }

    #[test]
    fn known_slack_sender_resolves_with_correct_tier() {
        let config = default_config();
        let origin = ActionOrigin::BridgeSlack {
            user_id: "SEBASTIAN_SLACK_ID".into(),
            channel_id: "C_GENERAL".into(),
        };
        let user = resolve_identity(&config, &origin).expect("should resolve");
        assert_eq!(user.display_name, "Sebastian");
        assert_eq!(user.tier_ceiling, Tier::T3);
    }

    #[test]
    fn paul_tier_ceiling_is_t1() {
        let config = default_config();
        let origin = ActionOrigin::BridgeSlack {
            user_id: "PAUL_SLACK_ID".into(),
            channel_id: "C_GENERAL".into(),
        };
        let user = resolve_identity(&config, &origin).expect("should resolve");
        assert_eq!(user.display_name, "Paul");
        assert_eq!(user.tier_ceiling, Tier::T1);
    }

    #[test]
    fn non_bridge_origin_returns_error() {
        let config = default_config();
        let origin = ActionOrigin::LocalCli;
        let err = resolve_identity(&config, &origin).expect_err("should fail");
        assert!(matches!(err, BridgeError::UnknownSender { .. }));
    }
}
