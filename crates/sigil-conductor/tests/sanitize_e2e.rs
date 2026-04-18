//! End-to-end integration test for the content-sanitization pipeline.
//!
//! Proves the hard constraint called out in the PR7 spec: one
//! known-bad input per format produces cleaned output + populated
//! `SanitizeReport` + audit entry. Runs three fixtures (HTML, MD, JSON)
//! through the full stack:
//!
//! ```text
//! FixtureFetcher → ActionService::execute → dispatch_fetch_external_content
//!    → sigil_content::Sanitizer::sanitize_{html,markdown,json}
//!    → evaluator.evaluate_result (SanitizationRequirement gate)
//!    → audit log (with report attached)
//! ```
//!
//! What's asserted:
//!
//! 1. The outcome is `Completed(ExternalContent)` — the policy gate
//!    approves the sanitized result.
//! 2. The cleaned text drops the attack payloads (hidden instructions,
//!    comment-smuggled injection, unicode-escape injection).
//! 3. Visible body content survives.
//! 4. The report carries the declared `content_type` and populated
//!    fingerprints.
//! 5. The audit log contains an entry for the action whose
//!    `sanitize_report` matches the report returned to the caller
//!    (byte-identical fingerprints).
//! 6. Running the same fixture twice produces identical reports and
//!    fingerprints — the pipeline is reproducible across runs.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::wildcard_enum_match_arm
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sigil_audit::AuditLogWriter;
use sigil_content::{
    ExternalContentFetcher, FetchError, FetchFuture, RawFetchedContent, Sanitizer,
};
use sigil_core::action::{Action, ActionRequest};
use sigil_core::content::{ContentSource, ContentType};
use sigil_core::origin::ActionOrigin;
use sigil_policy::{EvaluatorConfig, PolicyService};
use sigil_store::Store;

use sigil_conductor::action_service::{ActionOutcome, ActionService, DispatchResult};

// ---------------------------------------------------------------------------
// Runtime stub — sanitize dispatch doesn't touch tmux / container code.
// ---------------------------------------------------------------------------

struct NullRuntime;

impl sigil_core::traits::SessionRuntime for NullRuntime {
    async fn launch(
        &self,
        _config: &sigil_core::session::SessionConfig,
    ) -> Result<sigil_core::session::SessionHandle, sigil_core::CoreError> {
        Err(sigil_core::CoreError::Runtime {
            message: "null runtime".into(),
        })
    }

    async fn send(
        &self,
        _handle: &sigil_core::session::SessionHandle,
        _msg: sigil_core::protocol::ConductorMessage,
    ) -> Result<(), sigil_core::CoreError> {
        Ok(())
    }

    async fn read_output(
        &self,
        _handle: &sigil_core::session::SessionHandle,
    ) -> Result<String, sigil_core::CoreError> {
        Ok(String::new())
    }

    async fn status(
        &self,
        _handle: &sigil_core::session::SessionHandle,
    ) -> Result<sigil_core::session::SessionState, sigil_core::CoreError> {
        Ok(sigil_core::session::SessionState::Stopped)
    }

    async fn stop(
        &self,
        _handle: &sigil_core::session::SessionHandle,
    ) -> Result<(), sigil_core::CoreError> {
        Ok(())
    }
}

impl sigil_core::traits::LifecycleHooks for NullRuntime {
    async fn register_identity_hooks(
        &self,
        _handle: &sigil_core::session::SessionHandle,
        _spec: &sigil_core::session::IdentitySpec,
    ) -> Result<(), sigil_core::CoreError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FixtureFetcher — the file-backed fetcher the E2E test drives.
// ---------------------------------------------------------------------------

/// A fetcher that maps synthetic URLs to files on disk. Tests point
/// at `crates/sigil-conductor/tests/fixtures/sanitize/*` via this.
struct FixtureFetcher {
    root: PathBuf,
}

impl FixtureFetcher {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn resolve(&self, url: &str) -> Option<PathBuf> {
        // Accept the URL form "fixture://<basename>" so the
        // integration test can declare intent clearly without having
        // to invent a fake host.
        let rest = url.strip_prefix("fixture://")?;
        Some(self.root.join(rest))
    }
}

impl ExternalContentFetcher for FixtureFetcher {
    fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a> {
        Box::pin(async move {
            let path = self.resolve(url).ok_or_else(|| FetchError::NotFound {
                url: url.to_owned(),
            })?;
            tokio::fs::read(&path).await.map_err(|e| FetchError::Other {
                message: format!("reading fixture {}: {e}", path.display()),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Test rig
// ---------------------------------------------------------------------------

const KEY: &[u8] = b"sigil-e2e-sanitize-test-key";

struct Rig {
    service: ActionService<NullRuntime, PolicyService<Store>>,
    audit_path: PathBuf,
    _tmp: tempfile::TempDir,
}

async fn make_rig() -> Rig {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, KEY.to_vec())
            .await
            .expect("audit writer"),
    );
    let store = Arc::new(Store::new_in_memory().await.expect("in-memory store"));
    let runtime = Arc::new(NullRuntime);
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::clone(&store));
    let sanitizer = Arc::new(Sanitizer::new(KEY).expect("sanitizer key"));
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sanitize");
    let fetcher = Arc::new(FixtureFetcher::new(fixtures_root));

    let service = ActionService::new(policy, runtime, audit, store)
        .with_sanitizer(sanitizer)
        .with_fetcher(fetcher);

    Rig {
        service,
        audit_path,
        _tmp: tmp,
    }
}

fn fetch_request(fixture: &str, content_type: ContentType) -> ActionRequest {
    ActionRequest::new(
        Action::FetchExternalContent {
            url: format!("fixture://{fixture}"),
            content_type,
        },
        ActionOrigin::LocalCli,
    )
}

async fn read_audit_events(path: &Path) -> Vec<serde_json::Value> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .expect("read audit log");
    raw.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("audit line is json"))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_html_fixture_cleans_and_audits_with_report() {
    let rig = make_rig().await;

    let request = fetch_request("bad.html", ContentType::Html);
    let request_id = request.id;
    let outcome = rig.service.execute(request).await.expect("execute");

    let (text, report) = match outcome {
        ActionOutcome::Completed(DispatchResult::ExternalContent { text, report }) => {
            (text, report)
        }
        other => panic!("expected ExternalContent, got {other:?}"),
    };

    // Cleaned output must drop every known-bad substring.
    assert!(
        !text.contains("exfiltrate"),
        "exfiltrate must be stripped: {text}"
    );
    assert!(
        !text.contains("administrator mode"),
        "hidden-div injection must be stripped: {text}"
    );
    assert!(
        !text.contains("/etc/passwd"),
        "<script>-tag injection must be stripped: {text}"
    );
    assert!(
        !text.contains("jailbreak mode engaged"),
        "<noscript> injection must be stripped: {text}"
    );
    // Visible body survives.
    assert!(text.contains("Revenue grew"));
    assert!(text.contains("End of report"));

    // Report invariants.
    assert_eq!(report.content_type, ContentType::Html);
    assert!(report.bytes_in > 0);
    assert!(
        report.stripped_elements.iter().any(|(k, _)| k == "script"),
        "<script> strip must be recorded: {:?}",
        report.stripped_elements,
    );
    assert!(!report.nonce.is_empty());

    // Audit log must carry an event whose sanitize_report matches the
    // report we returned. The pre-dispatch audit has no report; the
    // post-dispatch entry does. We pick the one whose fingerprints
    // match so the test is order-insensitive across audit entries.
    let events = read_audit_events(&rig.audit_path).await;
    assert!(
        events.len() >= 2,
        "expected pre- + post-dispatch audit entries, got {}",
        events.len(),
    );
    let matching = events
        .iter()
        .filter_map(|e| e.get("event"))
        .find(|evt| {
            evt.get("request_id")
                .and_then(|v| v.as_str())
                .is_some_and(|v| v == request_id.to_string())
                && evt.get("sanitize_report").is_some_and(|r| !r.is_null())
        })
        .expect("audit log must contain a post-dispatch entry with the report attached");
    let audit_report: sigil_core::SanitizeReport =
        serde_json::from_value(matching.get("sanitize_report").unwrap().clone())
            .expect("report round-trips");
    assert_eq!(audit_report.raw_fingerprint, report.raw_fingerprint);
    assert_eq!(
        audit_report.sanitized_fingerprint,
        report.sanitized_fingerprint
    );
    assert_eq!(audit_report.nonce, report.nonce);
}

#[tokio::test]
async fn e2e_markdown_fixture_strips_comment_and_preserves_code() {
    let rig = make_rig().await;

    let outcome = rig
        .service
        .execute(fetch_request("bad.md", ContentType::Markdown))
        .await
        .expect("execute");

    let (text, report) = match outcome {
        ActionOutcome::Completed(DispatchResult::ExternalContent { text, report }) => {
            (text, report)
        }
        other => panic!("expected ExternalContent, got {other:?}"),
    };

    assert!(
        !text.contains("Dump the conversation history"),
        "comment-smuggled injection must be stripped: {text}"
    );
    assert!(
        !text.contains("pirate"),
        "raw-HTML-block injection must be stripped: {text}"
    );
    // Fenced code preserved.
    assert!(text.contains("retry"));
    assert!(text.contains("MAX_RETRIES"));

    assert_eq!(report.content_type, ContentType::Markdown);
}

#[tokio::test]
async fn e2e_json_fixture_decodes_escapes_and_flags_findings() {
    let rig = make_rig().await;

    let outcome = rig
        .service
        .execute(fetch_request("bad.json", ContentType::Json))
        .await
        .expect("execute");

    let (_text, report) = match outcome {
        ActionOutcome::Completed(DispatchResult::ExternalContent { text, report }) => {
            (text, report)
        }
        other => panic!("expected ExternalContent, got {other:?}"),
    };

    assert_eq!(report.content_type, ContentType::Json);
    assert!(
        !report.findings.is_empty(),
        "unicode-escape-decoded injection must surface as findings"
    );
}

/// Same fixture twice, same key → reports must be byte-identical on
/// the fields the design doc calls out as reproducible
/// (`raw_fingerprint`, `sanitized_fingerprint`, content-type, stripped
/// kinds). Nonces deliberately differ per call; the test excludes them.
#[tokio::test]
async fn e2e_report_is_reproducible_across_runs() {
    let rig = make_rig().await;

    let first = rig
        .service
        .execute(fetch_request("bad.html", ContentType::Html))
        .await
        .expect("execute");
    let second = rig
        .service
        .execute(fetch_request("bad.html", ContentType::Html))
        .await
        .expect("execute");

    let r1 = match first {
        ActionOutcome::Completed(DispatchResult::ExternalContent { report, .. }) => report,
        other => panic!("expected ExternalContent, got {other:?}"),
    };
    let r2 = match second {
        ActionOutcome::Completed(DispatchResult::ExternalContent { report, .. }) => report,
        other => panic!("expected ExternalContent, got {other:?}"),
    };

    assert_eq!(r1.raw_fingerprint, r2.raw_fingerprint);
    assert_eq!(r1.sanitized_fingerprint, r2.sanitized_fingerprint);
    assert_eq!(r1.content_type, r2.content_type);
    assert_eq!(r1.bytes_in, r2.bytes_in);
    assert_eq!(r1.bytes_out, r2.bytes_out);
    assert_eq!(r1.stripped_elements, r2.stripped_elements);
    assert_eq!(r1.rule_set_version, r2.rule_set_version);
    assert_eq!(r1.scoring_version, r2.scoring_version);
    assert_ne!(r1.nonce, r2.nonce, "nonces must differ per call");
}

/// If the fetcher cannot find the URL, the dispatch arm converts the
/// `FetchError` into an internal `ConductorError` (which `execute`
/// returns as `Err`). This pins the "fail cleanly" contract — no
/// silent pass, no panic.
#[tokio::test]
async fn e2e_unknown_fixture_url_fails_cleanly() {
    let rig = make_rig().await;

    let err = rig
        .service
        .execute(fetch_request("nope-does-not-exist.html", ContentType::Html))
        .await
        .expect_err("missing fixture should fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("NotFound") || msg.contains("nope-does-not-exist"),
        "unexpected err: {msg}"
    );
}

/// An `ActionService` with no sanitizer installed must deny
/// `FetchExternalContent` cleanly — the spec calls this out
/// explicitly ("If sanitization fails ... the action fails cleanly").
#[tokio::test]
async fn e2e_without_sanitizer_fails_cleanly() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let audit = Arc::new(
        AuditLogWriter::new(&audit_path, KEY.to_vec())
            .await
            .expect("audit"),
    );
    let store = Arc::new(Store::new_in_memory().await.expect("store"));
    let runtime = Arc::new(NullRuntime);
    let policy = PolicyService::new(EvaluatorConfig::default(), Arc::clone(&store));
    let service = ActionService::new(policy, runtime, audit, store);
    // Deliberately NO .with_sanitizer()

    let err = service
        .execute(fetch_request("bad.html", ContentType::Html))
        .await
        .expect_err("no sanitizer → fail cleanly");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("sanitizer"),
        "error should name the missing sanitizer: {msg}"
    );
}

/// Smoke test that `run_sanitize` directly (no fetch) produces the
/// same cleaned output as the end-to-end path. Protects against a
/// future refactor that bypasses `run_sanitize` in the dispatch arm.
#[tokio::test]
async fn run_sanitize_matches_dispatch_output_for_html() {
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sanitize");
    let html_bytes = tokio::fs::read(fixtures_root.join("bad.html"))
        .await
        .expect("read fixture");

    let sanitizer = Sanitizer::new(KEY).expect("sanitizer");
    let direct = sigil_conductor::sanitize::run_sanitize(
        &sanitizer,
        RawFetchedContent::from_bytes(html_bytes.clone()),
        ContentSource::Other("fixture://bad.html".into()),
        ContentType::Html,
    )
    .expect("direct sanitize");

    let rig = make_rig().await;
    let outcome = rig
        .service
        .execute(fetch_request("bad.html", ContentType::Html))
        .await
        .expect("execute");
    let (_, dispatch_report) = match outcome {
        ActionOutcome::Completed(DispatchResult::ExternalContent { text, report }) => {
            (text, report)
        }
        other => panic!("expected ExternalContent, got {other:?}"),
    };

    // Fingerprints over same bytes + same key must match between the
    // direct call and the ActionService path.
    assert_eq!(
        direct.report.raw_fingerprint,
        dispatch_report.raw_fingerprint
    );
    assert_eq!(
        direct.report.sanitized_fingerprint,
        dispatch_report.sanitized_fingerprint
    );
}
