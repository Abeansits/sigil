//! Approval grant management.
//!
//! Grants are time-limited, use-limited tokens that elevate a principal's
//! tier for a specific capability and optional resource scope. They are
//! issued by a human (typically Sebastian via Telegram/CLI) and consumed
//! by the policy evaluator.

use std::future::Future;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use sigil_core::id::RequestId;
use sigil_core::trust::Capability;

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
        // Proper path boundary check: exact match OR prefix ending at a `/` boundary.
        // This prevents `/home/paul` from matching `/home/paulie/secret`.
        match (&self.resource_scope, resource) {
            (Some(scope), Some(res)) => matches_resource_scope(scope, res),
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    /// Increment the use counter.
    pub fn consume(&mut self) {
        self.uses = self.uses.saturating_add(1);
    }
}

/// Check whether a resource matches a grant scope with proper path boundaries.
///
/// Returns `true` if `resource` equals `scope` exactly, or if `resource`
/// starts with `scope` at a `/` boundary. This prevents `/home/paul` from
/// matching `/home/paulie/secret`.
fn matches_resource_scope(scope: &str, resource: &str) -> bool {
    if resource == scope {
        return true;
    }
    if !resource.starts_with(scope) {
        return false;
    }
    // The prefix matched — now ensure it's at a path boundary.
    // Either the scope already ends with '/' (e.g., "/home/paul/")
    // or the next character in resource after scope is '/'.
    scope.ends_with('/') || resource.as_bytes().get(scope.len()) == Some(&b'/')
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

/// A grant store that always returns no grants.
///
/// Used when no real store is available (e.g., in tests or when the
/// evaluator is constructed without a backing database).
#[derive(Clone, Debug)]
pub struct NoopGrantStore;

impl GrantStore for NoopGrantStore {
    async fn find_grant(
        &self,
        _principal: &str,
        _capability: Capability,
        _resource: Option<&str>,
    ) -> Result<Option<ApprovalGrant>, PolicyError> {
        Ok(None)
    }

    async fn save_grant(&self, _grant: &ApprovalGrant) -> Result<(), PolicyError> {
        Ok(())
    }
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
    fn scoped_grant_rejects_adjacent_path_without_boundary() {
        // /home/paul must NOT match /home/paulie/secret
        let grant = make_grant(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paul"),
            300,
            None,
        );
        assert!(!grant.matches(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paulie/secret"),
        ));
    }

    #[test]
    fn scoped_grant_matches_exact_scope() {
        let grant = make_grant(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paul"),
            300,
            None,
        );
        assert!(grant.matches("paul", Capability::ReadHostFile, Some("/home/paul"),));
    }

    #[test]
    fn scoped_grant_matches_with_slash_boundary() {
        // /home/paul should match /home/paul/docs/file.txt (boundary at /)
        let grant = make_grant(
            "paul",
            Capability::ReadHostFile,
            Some("/home/paul"),
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
    fn matches_resource_scope_boundary_cases() {
        // Exact match
        assert!(matches_resource_scope("/home/paul", "/home/paul"));
        // Proper path boundary
        assert!(matches_resource_scope("/home/paul", "/home/paul/secret"));
        // Scope with trailing slash
        assert!(matches_resource_scope("/home/paul/", "/home/paul/secret"));
        // Adjacent path — NOT a boundary match
        assert!(!matches_resource_scope("/home/paul", "/home/paulie"));
        assert!(!matches_resource_scope("/home/paul", "/home/paulie/secret"));
        // Completely different path
        assert!(!matches_resource_scope("/home/paul", "/etc/shadow"));
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

#[cfg(test)]
mod proptest_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use proptest::prelude::*;
    use sigil_core::trust::Capability;

    use super::*;

    // ── Resource scope matching ───────────────────────────────────

    proptest! {
        /// Exact match is always accepted: `matches_resource_scope(s, s)`.
        #[test]
        fn scope_exact_match_is_reflexive(scope in "[a-z/]{1,30}") {
            prop_assert!(
                matches_resource_scope(&scope, &scope),
                "exact match should always succeed for {scope:?}"
            );
        }

        /// Prefix with a slash boundary always matches.
        #[test]
        fn scope_prefix_with_slash_boundary_matches(
            scope in "/[a-z]{1,15}(/[a-z]{1,10}){0,3}",
            suffix in "[a-z]{1,15}(/[a-z]{1,10}){0,3}",
        ) {
            let resource = format!("{scope}/{suffix}");
            prop_assert!(
                matches_resource_scope(&scope, &resource),
                "{scope:?} should match {resource:?} (slash boundary)"
            );
        }

        /// A prefix without a path boundary must NOT match.
        /// scope = "/abc", resource = "/abcdef" — no slash at boundary.
        #[test]
        fn scope_prefix_without_boundary_rejects(
            scope in "/[a-z]{2,15}",
            extra in "[a-z]{1,10}",
        ) {
            let resource = format!("{scope}{extra}");
            prop_assert!(
                !matches_resource_scope(&scope, &resource),
                "{scope:?} should NOT match {resource:?} (no boundary)"
            );
        }

        /// Completely disjoint paths never match.
        #[test]
        fn disjoint_paths_never_match(
            scope in "/[a-z]{1,10}",
            resource in "/[A-Z]{1,10}",
        ) {
            // scope is lowercase, resource is uppercase → no prefix match.
            prop_assert!(
                !matches_resource_scope(&scope, &resource),
                "{scope:?} should NOT match {resource:?}"
            );
        }
    }

    // ── Grant.matches() symmetry ──────────────────────────────────

    fn arb_capability() -> impl Strategy<Value = Capability> {
        prop_oneof![
            Just(Capability::ReadSessionInfo),
            Just(Capability::ReadSystemStatus),
            Just(Capability::ManageSession),
            Just(Capability::SendMessage),
            Just(Capability::ModifyInfrastructure),
            Just(Capability::ConfigureConductor),
            Just(Capability::ReadHostFile),
            Just(Capability::WriteHostFile),
            Just(Capability::ExecuteHostCommand),
            Just(Capability::ModifyGitState),
        ]
    }

    fn arb_capability_2() -> impl Strategy<Value = Capability> {
        prop_oneof![
            Just(Capability::ExternalNetworkWrite),
            Just(Capability::ServiceControl),
            Just(Capability::BreakGlass),
        ]
    }

    fn make_test_grant(
        principal: &str,
        capability: Capability,
        resource_scope: Option<&str>,
    ) -> ApprovalGrant {
        let now = OffsetDateTime::now_utc();
        ApprovalGrant {
            id: RequestId::new(),
            principal_id: principal.into(),
            capability,
            resource_scope: resource_scope.map(Into::into),
            expires_at: now + time::Duration::seconds(300),
            max_uses: None,
            uses: 0,
            issued_by: "test".into(),
            issued_at: now,
        }
    }

    proptest! {
        /// A grant always matches its own principal + capability.
        #[test]
        fn grant_matches_own_identity(
            principal in "[a-z]{1,10}",
            cap in arb_capability(),
        ) {
            let grant = make_test_grant(&principal, cap, None);
            prop_assert!(grant.matches(&principal, cap, None));
        }

        /// A grant never matches a different principal.
        #[test]
        fn grant_rejects_wrong_principal(
            owner in "[a-z]{1,10}",
            intruder in "[A-Z]{1,10}",
            cap in arb_capability(),
        ) {
            let grant = make_test_grant(&owner, cap, None);
            prop_assert!(
                !grant.matches(&intruder, cap, None),
                "grant for {owner:?} should reject {intruder:?}"
            );
        }

        /// A grant never matches a different capability.
        #[test]
        fn grant_rejects_wrong_capability(
            principal in "[a-z]{1,10}",
            cap_a in arb_capability(),
            cap_b in arb_capability_2(),
        ) {
            // cap_a from first group, cap_b from second → always different.
            let grant = make_test_grant(&principal, cap_a, None);
            prop_assert!(
                !grant.matches(&principal, cap_b, None),
                "grant for {cap_a:?} should reject {cap_b:?}"
            );
        }
    }
}
