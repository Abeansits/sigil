//! Integration coverage for `sigil session send --wait --timeout` and
//! `--no-wait` — the agent-deck parity flags Vigil uses daily.
//!
//! These tests exercise the CLI handler directly against a scripted
//! `SessionRuntime` stub so we don't need tmux. The goal is to pin
//! three behaviours so a refactor can't silently regress:
//!
//! 1. `--wait` with a reply arriving before the deadline → succeeds,
//!    consumes the mock's output, prints it.
//! 2. `--wait` with a session that stays `Running` past the deadline
//!    → fails with an actionable error instead of hanging forever or
//!    silently returning success.
//! 3. `--no-wait` → returns immediately after delivery, regardless of
//!    runtime state. (Also the closest thing to a "heartbeat" path.)

#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sigil_audit::AuditLogWriter;
use sigil_cli::SessionCommands;
use sigil_conductor::action_service::ActionService;
use sigil_core::error::CoreError;
use sigil_core::protocol::ConductorMessage;
use sigil_core::session::{
    IdentitySpec, SessionConfig, SessionHandle, SessionRecord, SessionState, ToolKind,
};
use sigil_core::traits::{LifecycleHooks, SessionRuntime};
use sigil_policy::{EvaluatorConfig, NoopGrantStore, PolicyService};
use sigil_store::Store;
use tempfile::TempDir;

/// Scripted runtime whose `status()` return value depends on how many
/// times it has been called. Used to simulate a session that replies
/// after N polls (for the success path) or never replies (timeout
/// path).
struct ScriptedRuntime {
    /// Number of `status()` calls that should still return `Running`
    /// before transitioning to `after`.
    running_until: usize,
    /// State to report once `running_until` calls have elapsed.
    after: SessionState,
    /// Text that `read_output` returns. Asserted on the success path.
    output: String,
    /// How many times `status()` was called.
    status_calls: AtomicUsize,
    /// How many times `send()` was called.
    send_calls: AtomicUsize,
}

impl ScriptedRuntime {
    fn new(running_until: usize, after: SessionState, output: &str) -> Self {
        Self {
            running_until,
            after,
            output: output.to_owned(),
            status_calls: AtomicUsize::new(0),
            send_calls: AtomicUsize::new(0),
        }
    }

    fn status_calls(&self) -> usize {
        self.status_calls.load(Ordering::SeqCst)
    }

    fn send_calls(&self) -> usize {
        self.send_calls.load(Ordering::SeqCst)
    }
}

impl SessionRuntime for ScriptedRuntime {
    async fn launch(&self, _config: &SessionConfig) -> Result<SessionHandle, CoreError> {
        Err(CoreError::Runtime {
            message: "scripted runtime: launch not used".into(),
        })
    }

    async fn send(&self, _handle: &SessionHandle, _msg: ConductorMessage) -> Result<(), CoreError> {
        self.send_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn read_output(&self, _handle: &SessionHandle) -> Result<String, CoreError> {
        Ok(self.output.clone())
    }

    async fn status(&self, _handle: &SessionHandle) -> Result<SessionState, CoreError> {
        let prev = self.status_calls.fetch_add(1, Ordering::SeqCst);
        if prev < self.running_until {
            Ok(SessionState::Running)
        } else {
            Ok(self.after)
        }
    }

    async fn stop(&self, _handle: &SessionHandle) -> Result<(), CoreError> {
        Ok(())
    }
}

impl LifecycleHooks for ScriptedRuntime {
    async fn register_identity_hooks(
        &self,
        _handle: &SessionHandle,
        _spec: &IdentitySpec,
    ) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Spin up an in-memory store with a pre-registered running session and
/// an `ActionService` wired to `runtime`. Returns the tempdir so the
/// audit log's backing file outlives the test body.
async fn build_service(
    runtime: Arc<ScriptedRuntime>,
    title: &str,
) -> (
    ActionService<ScriptedRuntime, PolicyService<NoopGrantStore>>,
    TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = Arc::new(
        AuditLogWriter::new(
            &dir.path().join("audit.jsonl"),
            b"session-send-timeout-test-key".to_vec(),
        )
        .await
        .expect("audit writer"),
    );
    let store = Arc::new(Store::new_in_memory().await.expect("store"));

    let record = SessionRecord {
        id: sigil_core::id::SessionId::new(),
        title: title.into(),
        path: PathBuf::from("/tmp/session-send-timeout-test"),
        tool: ToolKind::ClaudeCode,
        group: None,
        parent: None,
        execution_class: sigil_core::trust::ExecutionClass::OfflineWorker,
        sandboxed: true,
        state: SessionState::Running,
        identity: None,
    };
    store
        .create_session(&record)
        .await
        .expect("register session");

    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::new(NoopGrantStore));
    let service = ActionService::new(policy, runtime, audit, store);
    (service, dir)
}

// These tests run in real Tokio time (no `tokio::time::pause()`) —
// pausing after setup still makes sqlx's pool acquire-timer fire on
// the next DB call under paused time, which manifested as flaky CI
// "pool timed out" failures. Small `--timeout` values keep the two
// `--wait` tests bounded to ~2s wall-clock each.

#[tokio::test]
async fn send_wait_succeeds_when_reply_arrives_before_timeout() {
    // Mock transitions to Waiting on the first status() call, so the
    // very first poll after `send()` sees a non-Running state and the
    // command reads output and returns.
    let runtime = Arc::new(ScriptedRuntime::new(
        0, // running_until = 0 → first status() returns `after`.
        SessionState::Waiting,
        "mock output captured after reply",
    ));
    let (service, _dir) = build_service(Arc::clone(&runtime), "timeout-success").await;

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: "timeout-success".into(),
            message: "ping".into(),
            wait: true,
            no_wait: false,
            quiet: true,
            timeout: Some(Duration::from_secs(10)),
        },
    )
    .await
    .expect("send --wait should succeed");

    assert_eq!(runtime.send_calls(), 1, "send() should fire exactly once");
    assert_eq!(
        runtime.status_calls(),
        1,
        "first status() poll should see the reply and exit the loop",
    );
}

#[tokio::test]
async fn send_wait_times_out_with_actionable_error() {
    // Mock never leaves Running, so the poll loop must give up at the
    // deadline rather than looping forever.
    let runtime = Arc::new(ScriptedRuntime::new(
        usize::MAX,
        SessionState::Running,
        "never read",
    ));
    let (service, _dir) = build_service(Arc::clone(&runtime), "timeout-fail").await;

    let err = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: "timeout-fail".into(),
            message: "hang forever please".into(),
            wait: true,
            no_wait: false,
            quiet: true,
            timeout: Some(Duration::from_secs(1)),
        },
    )
    .await
    .expect_err("send --wait --timeout=1 should error, not hang");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("timed out") && msg.contains("timeout-fail"),
        "error should name both the timeout condition and session, got: {msg}",
    );
    assert!(
        msg.contains("--no-wait") || msg.contains("--timeout"),
        "error should suggest a recovery action, got: {msg}",
    );
    assert!(
        msg.contains("sigil session output"),
        "error should point at `sigil session output` for partial-output recovery, got: {msg}",
    );
    assert_eq!(
        runtime.send_calls(),
        1,
        "send() should still have fired exactly once before the wait",
    );
    // `--timeout 1` with a 2s poll interval: first iteration sleeps 1s
    // (capped to the remaining budget), polls, still Running, second
    // iteration sees the deadline and bails. So we expect exactly one
    // status poll before the hard failure.
    assert_eq!(
        runtime.status_calls(),
        1,
        "deadline must be enforced per-iteration, not rounded up to a full poll interval",
    );
}

#[tokio::test]
async fn send_no_wait_returns_immediately() {
    // Even though the mock would claim `Running` forever, `--no-wait`
    // means the handler never polls — it returns as soon as the
    // message is delivered.
    let runtime = Arc::new(ScriptedRuntime::new(
        usize::MAX,
        SessionState::Running,
        "never read",
    ));
    let (service, _dir) = build_service(Arc::clone(&runtime), "heartbeat").await;

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: "heartbeat".into(),
            message: "still alive".into(),
            wait: false,
            no_wait: true,
            quiet: true,
            timeout: None,
        },
    )
    .await
    .expect("send --no-wait should succeed immediately");

    assert_eq!(runtime.send_calls(), 1, "send() should fire exactly once");
    assert_eq!(
        runtime.status_calls(),
        0,
        "--no-wait must not poll status at all",
    );
}

#[tokio::test]
async fn send_default_is_fire_and_forget() {
    // Same shape as --no-wait, but via the default (neither --wait nor
    // --no-wait). Pins the documented default behaviour so a future
    // change to "wait by default" can't land silently.
    let runtime = Arc::new(ScriptedRuntime::new(
        usize::MAX,
        SessionState::Running,
        "never read",
    ));
    let (service, _dir) = build_service(Arc::clone(&runtime), "default-fire-and-forget").await;

    sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: "default-fire-and-forget".into(),
            message: "ping".into(),
            wait: false,
            no_wait: false,
            quiet: true,
            timeout: None,
        },
    )
    .await
    .expect("default send should succeed");

    assert_eq!(runtime.send_calls(), 1);
    assert_eq!(
        runtime.status_calls(),
        0,
        "absence of --wait must mean no status polling",
    );
}

// `--timeout` requires `--wait`. Clap's `requires` silently passes when
// `--no-wait` is also present, so enforcement lives in the dispatcher.
// Both shapes (implicit and explicit fire-and-forget) must fail.

#[tokio::test]
async fn send_timeout_without_wait_is_rejected() {
    let runtime = Arc::new(ScriptedRuntime::new(
        usize::MAX,
        SessionState::Running,
        "never read",
    ));
    let (service, _dir) = build_service(Arc::clone(&runtime), "reject-implicit").await;

    let err = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: "reject-implicit".into(),
            message: "ping".into(),
            wait: false,
            no_wait: false,
            quiet: true,
            timeout: Some(Duration::from_secs(30)),
        },
    )
    .await
    .expect_err("--timeout without --wait must error");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("--timeout") && msg.contains("--wait"),
        "error should name both flags so the fix is obvious, got: {msg}",
    );
    assert_eq!(
        runtime.send_calls(),
        0,
        "rejection must precede any side-effect on the runtime",
    );
}

#[tokio::test]
async fn send_timeout_with_explicit_no_wait_is_rejected() {
    let runtime = Arc::new(ScriptedRuntime::new(
        usize::MAX,
        SessionState::Running,
        "never read",
    ));
    let (service, _dir) = build_service(Arc::clone(&runtime), "reject-no-wait").await;

    let err = sigil_cli::commands::session::run(
        &service,
        SessionCommands::Send {
            name: "reject-no-wait".into(),
            message: "ping".into(),
            wait: false,
            no_wait: true,
            quiet: true,
            timeout: Some(Duration::from_secs(30)),
        },
    )
    .await
    .expect_err("--timeout with --no-wait must error");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("--timeout") && msg.contains("--wait"),
        "error should name both flags, got: {msg}",
    );
    assert_eq!(runtime.send_calls(), 0);
}
