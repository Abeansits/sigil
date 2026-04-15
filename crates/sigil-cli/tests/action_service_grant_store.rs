//! Integration: `ActionService` + real `Store` as `GrantStore`.
//!
//! Exercises the topology wired in `sigil-cli::lib::build_action_service`
//! where the sqlite `Store` also satisfies `GrantStore`. Without this
//! test the path from "grant persisted in DB" → "policy consults grant"
//! → "privileged action allowed" had no end-to-end coverage.
//!
//! Scenario:
//! 1. Baseline: `LocalCli` requesting a `T3` host read needs approval.
//! 2. Persist a grant via the `Store`'s `GrantStore` impl.
//! 3. Same action now evaluates to `Allow` (grant consumed).
//! 4. After the single-use grant is exhausted, the action needs approval
//!    again — verifies that revoked/spent grants do not leak authority.

#![allow(clippy::expect_used, clippy::panic, clippy::wildcard_enum_match_arm)]

use std::path::PathBuf;
use std::sync::Arc;

use sigil_audit::AuditLogWriter;
use sigil_conductor::action_service::{ActionOutcome, ActionService, DispatchResult};
use sigil_core::action::{Action, ActionRequest};
use sigil_core::error::CoreError;
use sigil_core::id::RequestId;
use sigil_core::origin::ActionOrigin;
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{IdentitySpec, SessionConfig, SessionHandle, SessionState};
use sigil_core::traits::{LifecycleHooks, SessionRuntime};
use sigil_core::trust::Capability;
use sigil_policy::grants::{ApprovalGrant, GrantStore};
use sigil_policy::{EvaluatorConfig, PolicyService};
use sigil_store::Store;
use time::OffsetDateTime;

/// Runtime stub: the T3 `ReadHostFile` action is `AuthorizedNotDispatched`
/// in `ActionService`, so the runtime is never called on the happy path.
/// The methods we do implement are no-ops — present only to satisfy the
/// trait bounds.
struct StubRuntime;

impl SessionRuntime for StubRuntime {
    async fn launch(&self, _config: &SessionConfig) -> Result<SessionHandle, CoreError> {
        Err(CoreError::Runtime {
            message: "stub runtime: launch not used".into(),
        })
    }

    async fn send(&self, _handle: &SessionHandle, _msg: ConductorMessage) -> Result<(), CoreError> {
        Ok(())
    }

    async fn read_output(&self, _handle: &SessionHandle) -> Result<String, CoreError> {
        Ok(String::new())
    }

    async fn status(&self, _handle: &SessionHandle) -> Result<SessionState, CoreError> {
        Ok(SessionState::Stopped)
    }

    async fn stop(&self, _handle: &SessionHandle) -> Result<(), CoreError> {
        Ok(())
    }
}

impl LifecycleHooks for StubRuntime {
    async fn register_identity_hooks(
        &self,
        _handle: &SessionHandle,
        _spec: &IdentitySpec,
    ) -> Result<(), CoreError> {
        Ok(())
    }
}

fn make_grant(
    principal: &str,
    capability: Capability,
    scope: Option<&str>,
    max_uses: Option<u32>,
) -> ApprovalGrant {
    let now = OffsetDateTime::now_utc();
    ApprovalGrant {
        id: RequestId::new(),
        principal_id: principal.into(),
        capability,
        resource_scope: scope.map(Into::into),
        expires_at: now + time::Duration::seconds(300),
        max_uses,
        uses: 0,
        issued_by: "sebastian".into(),
        issued_at: now,
    }
}

#[tokio::test]
async fn real_store_as_grant_store_gates_privileged_action() {
    let dir = tempfile::tempdir().expect("tempdir");
    // In-memory sqlite — exercises the same `GrantStore` impl as production.
    let store = Arc::new(Store::new_in_memory().await.expect("store"));
    let audit = Arc::new(
        AuditLogWriter::new(
            &dir.path().join("audit.jsonl"),
            b"grant-store-test-key".to_vec(),
        )
        .await
        .expect("audit writer"),
    );
    // Same wiring as `sigil-cli::lib`: Store satisfies `GrantStore`.
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::clone(&store));
    let runtime = Arc::new(StubRuntime);
    let service = ActionService::new(
        policy,
        Arc::clone(&runtime),
        Arc::clone(&audit),
        Arc::clone(&store),
    );

    // `LocalCli` → principal "sebastian" (T3Plus ceiling).
    // `ReadHostFile` is a T3 capability → hits `check_privileged_approval`,
    // which does NOT auto-allow `LocalCli` (only `HumanApproved` does).
    // Path is inside the scoped grant we'll persist below.
    let scope = "/tmp/sigil-grant-store-test/";
    let target = PathBuf::from("/tmp/sigil-grant-store-test/data.txt");

    // --- 1. Baseline: no grant → NeedsApproval ------------------------------
    let baseline = service
        .execute(ActionRequest::new(
            Action::ReadHostFile {
                path: target.clone(),
            },
            ActionOrigin::LocalCli,
        ))
        .await
        .expect("execute baseline");
    assert!(
        matches!(baseline, ActionOutcome::NeedsApproval { .. }),
        "expected NeedsApproval with no grant persisted, got {baseline:?}",
    );

    // --- 2. Persist a grant via Store's GrantStore impl ---------------------
    let grant = make_grant("sebastian", Capability::ReadHostFile, Some(scope), Some(1));
    GrantStore::save_grant(&*store, &grant)
        .await
        .expect("save grant through Store's GrantStore impl");

    // Sanity check: the grant we just wrote is findable via the same trait
    // impl the evaluator will use.
    let found = GrantStore::find_grant(&*store, "sebastian", Capability::ReadHostFile, Some(scope))
        .await
        .expect("find_grant");
    assert!(found.is_some(), "persisted grant should be findable");

    // --- 3. With grant → Allow, dispatch is AuthorizedNotDispatched --------
    let allowed = service
        .execute(ActionRequest::new(
            Action::ReadHostFile {
                path: target.clone(),
            },
            ActionOrigin::LocalCli,
        ))
        .await
        .expect("execute allowed");
    match allowed {
        ActionOutcome::Completed(DispatchResult::AuthorizedNotDispatched) => {}
        other => panic!("expected Completed(AuthorizedNotDispatched) after grant, got {other:?}"),
    }

    // --- 4. Grant is single-use → next call needs approval again -----------
    // Fail-closed regression: a consumed/revoked grant must not leak
    // authority to subsequent requests.
    let after_consume = service
        .execute(ActionRequest::new(
            Action::ReadHostFile {
                path: target.clone(),
            },
            ActionOrigin::LocalCli,
        ))
        .await
        .expect("execute after-consume");
    assert!(
        matches!(after_consume, ActionOutcome::NeedsApproval { .. }),
        "expected NeedsApproval after single-use grant exhausted, got {after_consume:?}",
    );

    // --- 5. Store confirms the grant is no longer findable -----------------
    // Complements the outcome check: the single-use grant must actually
    // be consumed in the DB, not just return NeedsApproval by chance.
    let exhausted =
        GrantStore::find_grant(&*store, "sebastian", Capability::ReadHostFile, Some(scope))
            .await
            .expect("find_grant after consume");
    assert!(
        exhausted.is_none(),
        "single-use grant should no longer be findable after consumption",
    );
}

/// Scope-boundary regression: a grant scoped to one path prefix must not
/// authorize a request targeting a different path that happens to share a
/// textual prefix. Catches `starts_with` without a `/` boundary check.
#[tokio::test]
async fn out_of_scope_grant_does_not_authorize() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::new_in_memory().await.expect("store"));
    let audit = Arc::new(
        AuditLogWriter::new(
            &dir.path().join("audit.jsonl"),
            b"scope-boundary-test-key".to_vec(),
        )
        .await
        .expect("audit writer"),
    );
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::clone(&store));
    let service = ActionService::new(policy, Arc::new(StubRuntime), audit, Arc::clone(&store));

    // Grant is scoped to "/tmp/sigil-scope/" — a request inside
    // "/tmp/sigil-scope-other/" shares the textual prefix but must NOT be
    // authorized.
    let grant = make_grant(
        "sebastian",
        Capability::ReadHostFile,
        Some("/tmp/sigil-scope/"),
        Some(5),
    );
    GrantStore::save_grant(&*store, &grant)
        .await
        .expect("save grant");

    let outcome = service
        .execute(ActionRequest::new(
            Action::ReadHostFile {
                path: PathBuf::from("/tmp/sigil-scope-other/file.txt"),
            },
            ActionOrigin::LocalCli,
        ))
        .await
        .expect("execute");
    assert!(
        matches!(outcome, ActionOutcome::NeedsApproval { .. }),
        "expected NeedsApproval for out-of-scope path, got {outcome:?}",
    );
}

#[tokio::test]
async fn expired_grant_is_not_honored_by_action_service() {
    // Second regression shape: an expired grant sitting in the DB must
    // not elevate authority. Uses the same Store-as-GrantStore wiring.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::new_in_memory().await.expect("store"));
    let audit = Arc::new(
        AuditLogWriter::new(
            &dir.path().join("audit.jsonl"),
            b"expired-grant-test-key".to_vec(),
        )
        .await
        .expect("audit writer"),
    );
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::clone(&store));
    let runtime = Arc::new(StubRuntime);
    let service = ActionService::new(policy, runtime, audit, Arc::clone(&store));

    let now = OffsetDateTime::now_utc();
    let expired = ApprovalGrant {
        id: RequestId::new(),
        principal_id: "sebastian".into(),
        capability: Capability::ReadHostFile,
        resource_scope: Some("/tmp/expired-test/".into()),
        // Expired 60 seconds ago.
        expires_at: now - time::Duration::seconds(60),
        max_uses: Some(5),
        uses: 0,
        issued_by: "sebastian".into(),
        issued_at: now - time::Duration::seconds(120),
    };
    GrantStore::save_grant(&*store, &expired)
        .await
        .expect("save expired grant");

    let outcome = service
        .execute(ActionRequest::new(
            Action::ReadHostFile {
                path: PathBuf::from("/tmp/expired-test/file.txt"),
            },
            ActionOrigin::LocalCli,
        ))
        .await
        .expect("execute");
    assert!(
        matches!(outcome, ActionOutcome::NeedsApproval { .. }),
        "expected NeedsApproval for expired grant, got {outcome:?}",
    );
}
