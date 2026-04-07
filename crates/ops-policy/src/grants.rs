//! Approval grant management.
//!
//! Grants are time-limited, use-limited tokens that elevate a principal's
//! tier for a specific capability and optional resource scope. They are
//! issued by a human (typically Sebastian via Telegram/CLI) and consumed
//! by the policy evaluator.

use std::future::Future;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use ops_core::id::RequestId;
use ops_core::trust::Capability;

use crate::error::PolicyError;

/// A time-limited, use-limited approval for a specific capability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalGrant {
    /// Unique identifier for this grant.
    pub id: RequestId,
    /// The principal this grant is issued to.
    pub principal_id: String,
    /// The capability being granted.
    pub capability: Capability,
    /// Optional resource scope (e.g., a file path pattern).
    pub resource_scope: Option<String>,
    /// When this grant expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Maximum number of times this grant can be used (`None` = unlimited).
    pub max_uses: Option<u32>,
    /// How many times this grant has been consumed.
    pub uses: u32,
    /// Who issued this grant.
    pub issued_by: String,
    /// When this grant was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
}

impl ApprovalGrant {
    /// Whether this grant is still valid (not expired, uses remaining).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let now = OffsetDateTime::now_utc();
        if now >= self.expires_at {
            return false;
        }
        match self.max_uses {
            Some(max) => self.uses < max,
            None => true,
        }
    }

    /// Whether this grant matches the given principal, capability, and
    /// optional resource.
    #[must_use]
    pub fn matches(&self, principal: &str, capability: Capability, resource: Option<&str>) -> bool {
        if self.principal_id != principal {
            return false;
        }
        if self.capability != capability {
            return false;
        }
        // If the grant has a resource scope, the request must match it.
        match (&self.resource_scope, resource) {
            (Some(scope), Some(res)) => res.starts_with(scope.as_str()),
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    /// Increment the use counter.
    pub fn consume(&mut self) {
        self.uses = self.uses.saturating_add(1);
    }
}

/// Async store for approval grants.
///
/// The policy evaluator uses this trait to look up and persist grants
/// without coupling to a specific storage backend.
pub trait GrantStore: Send + Sync {
    /// Find a valid grant matching the given criteria.
    fn find_grant(
        &self,
        principal: &str,
        capability: Capability,
        resource: Option<&str>,
    ) -> impl Future<Output = Result<Option<ApprovalGrant>, PolicyError>> + Send;

    /// Persist a grant (create or update).
    fn save_grant(
        &self,
        grant: &ApprovalGrant,
    ) -> impl Future<Output = Result<(), PolicyError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_grant(
        principal: &str,
        capability: Capability,
        resource_scope: Option<&str>,
        ttl_secs: i64,
        max_uses: Option<u32>,
    ) -> ApprovalGrant {
        let now = OffsetDateTime::now_utc();
        ApprovalGrant {
            id: RequestId::new(),
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

    #[test]
    fn fresh_grant_is_valid() {
        let grant = make_grant("paul", Capability::ReadHostFile, None, 300, Some(5));
        assert!(grant.is_valid());
    }

    #[test]
    fn expired_grant_is_invalid() {
        let now = OffsetDateTime::now_utc();
        let grant = ApprovalGrant {
            id: RequestId::new(),
            principal_id: "paul".into(),
            capability: Capability::ReadHostFile,
            resource_scope: None,
            expires_at: now - time::Duration::seconds(1),
            max_uses: None,
            uses: 0,
            issued_by: "sebastian".into(),
            issued_at: now - time::Duration::seconds(60),
        };
        assert!(!grant.is_valid());
    }

    #[test]
    fn exhausted_grant_is_invalid() {
        let grant = ApprovalGrant {
            uses: 5,
            ..make_grant("paul", Capability::ReadHostFile, None, 300, Some(5))
        };
        assert!(!grant.is_valid());
    }

    #[test]
    fn unlimited_uses_grant_stays_valid() {
        let mut grant = make_grant("paul", Capability::ReadHostFile, None, 300, None);
        for _ in 0..100 {
            grant.consume();
        }
        assert!(grant.is_valid());
    }

    #[test]
    fn matches_correct_principal_and_capability() {
        let grant = make_grant("paul", Capability::ReadHostFile, None, 300, None);
        assert!(grant.matches("paul", Capability::ReadHostFile, None));
    }

    #[test]
    fn rejects_wrong_principal() {
        let grant = make_grant("paul", Capability::ReadHostFile, None, 300, None);
        assert!(!grant.matches("eve", Capability::ReadHostFile, None));
    }

    #[test]
    fn rejects_wrong_capability() {
        let grant = make_grant("paul", Capability::ReadHostFile, None, 300, None);
        assert!(!grant.matches("paul", Capability::WriteHostFile, None));
    }

    #[test]
    fn scoped_grant_matches_resource_prefix() {
        let grant = make_grant(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paul/"),
            300,
            None,
        );
        assert!(grant.matches(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paul/docs/file.txt"),
        ));
    }

    #[test]
    fn scoped_grant_rejects_outside_scope() {
        let grant = make_grant(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paul/"),
            300,
            None,
        );
        assert!(!grant.matches("paul", Capability::ReadHostFile, Some("/etc/shadow"),));
    }

    #[test]
    fn scoped_grant_requires_resource_in_request() {
        let grant = make_grant(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paul/"),
            300,
            None,
        );
        assert!(!grant.matches("paul", Capability::ReadHostFile, None));
    }

    #[test]
    fn unscoped_grant_allows_any_resource() {
        let grant = make_grant("paul", Capability::ReadHostFile, None, 300, None);
        assert!(grant.matches("paul", Capability::ReadHostFile, Some("/etc/anything"),));
    }

    #[test]
    fn consume_increments_uses() {
        let mut grant = make_grant("paul", Capability::ReadHostFile, None, 300, Some(3));
        assert_eq!(grant.uses, 0);
        grant.consume();
        assert_eq!(grant.uses, 1);
        grant.consume();
        assert_eq!(grant.uses, 2);
        grant.consume();
        assert_eq!(grant.uses, 3);
        assert!(!grant.is_valid());
    }
}
