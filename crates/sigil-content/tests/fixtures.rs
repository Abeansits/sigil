//! Integration tests over the fixture corpora.
//!
//! Two corpora live under `crates/sigil-content/fixtures/`:
//!
//! - `malicious/` — red-team payloads. Each fixture is paired with an
//!   expected rule hit in [`MALICIOUS_EXPECTATIONS`]. A fixture that
//!   stops tripping its rule (or trips it at a weaker severity) fails
//!   the test, so severity demotions require a reviewable diff.
//! - `benign/` — real-world posts that legitimately discuss the attack
//!   surface the scanner flags. Provenance for each fixture lives in
//!   the per-file front-matter under `fixtures/benign/`. Drives the
//!   false-positive gate:
//!
//!     * `measured_hits <= baseline_hits + 1` at `risk_score >=
//!       RISK_GATE_THRESHOLD` (absolute delta, not percentage — see
//!       `content-sanitization.md` §Stage 5 for the rationale at
//!       `n=20`).
//!
//!   PR3.6 note: the previous "zero `FMT-001` hits specifically" hard
//!   gate was retired together with the FMT-001 severity demotion —
//!   the rule is now audit-only metadata, and the real attacker case
//!   (plain-text server serving an HTML body) is handled by the
//!   pre-dispatch reroute in `dispatch_sanitize`. The measured-hits
//!   delta check is the remaining regression detector.
//!
//! The baseline lives in `tests/fp_baseline.json`. CI reads it and
//! rejects any PR that raises the count by more than one fixture.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration tests fail loudly on invariant violations"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sigil_content::risk::RISK_GATE_THRESHOLD;
use sigil_content::wrap;
use sigil_content::{RawFetchedContent, Sanitizer, SanitizerConfig};
use sigil_core::{ContentSource, ContentType, Severity};

const TEST_KEY: &[u8] = b"sigil-content-fixture-test-key";

/// Marker prefix used by the benign-corpus fetcher when a URL failed to
/// resolve at capture time. Fixtures beginning with this token are
/// skipped by the FP gate instead of counting as zero-hit anchors —
/// otherwise a failed fetch would artificially relax the baseline.
const FETCH_FAILED_SENTINEL: &str = "# FETCH_FAILED";

/// `(fixture filename, expected rule id, expected severity or higher)`
///
/// "Or higher" semantics on severity: a future rule-set revision can
/// promote a rule (Medium → High) without breaking the fixture test.
/// Demotions still fail the test, which is the direction we care about.
const MALICIOUS_EXPECTATIONS: &[(&str, &str, Severity)] = &[
    ("inj_001.txt", "INJ-001", Severity::Medium),
    ("inj_002.txt", "INJ-002", Severity::Medium),
    ("inj_003.txt", "INJ-003", Severity::Medium),
    ("inj_004.txt", "INJ-004", Severity::Medium),
    ("inj_005.txt", "INJ-005", Severity::Medium),
    ("inj_006.txt", "INJ-006", Severity::Medium),
    ("inj_007.txt", "INJ-007", Severity::Low),
    ("enc_001.txt", "ENC-001", Severity::Low),
    ("enc_002.txt", "ENC-002", Severity::Low),
    ("enc_003.txt", "ENC-003", Severity::Medium),
    ("rep_001.txt", "REP-001", Severity::Low),
    ("rep_002.txt", "REP-002", Severity::Low),
    ("mix_001.txt", "MIX-001", Severity::Medium),
    // PR3.6: FMT-001 demoted from High to Info. The real attacker case
    // (plain-text server serving an HTML body) is handled earlier by the
    // pre-dispatch reroute in `dispatch_sanitize`; the pattern-scan
    // emission is now audit-only metadata.
    ("fmt_001.txt", "FMT-001", Severity::Info),
    ("fmt_001_fragment.txt", "FMT-001", Severity::Info),
    ("wrp_001.txt", "WRP-001", Severity::Info),
    ("delimiter_breakout.txt", "WRP-001", Severity::Info),
];

fn fixtures_dir(subdir: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("fixtures");
    p.push(subdir);
    p
}

fn tests_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p
}

fn sanitizer() -> Sanitizer {
    Sanitizer::with_config(TEST_KEY, SanitizerConfig::default()).expect("test key must be accepted")
}

fn read_fixture(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ---- Red-team corpus ---------------------------------------------------

#[test]
fn every_red_team_fixture_trips_its_rule() {
    let s = sanitizer();
    let dir = fixtures_dir("malicious");

    for (name, rule_id, min_severity) in MALICIOUS_EXPECTATIONS {
        let path = dir.join(name);
        let body = read_fixture(&path);
        let out = s
            .sanitize_plain(
                RawFetchedContent::from_string(body),
                ContentSource::File {
                    path: path.display().to_string(),
                },
                ContentType::PlainText,
            )
            .unwrap_or_else(|e| panic!("sanitize {name} failed: {e}"));

        let hit = out
            .report
            .findings
            .iter()
            .find(|f| f.rule_id == *rule_id)
            .unwrap_or_else(|| {
                panic!(
                    "fixture {name} did not trip {rule_id}: findings={:?}",
                    out.report
                        .findings
                        .iter()
                        .map(|f| &f.rule_id)
                        .collect::<Vec<_>>()
                )
            });

        assert!(
            hit.severity >= *min_severity,
            "fixture {name} rule {rule_id} severity regressed: expected >= {min_severity:?}, got {:?}",
            hit.severity,
        );
    }
}

#[test]
fn delimiter_breakout_payload_stays_inside_wrap() {
    let s = sanitizer();
    let path = fixtures_dir("malicious").join("delimiter_breakout.txt");
    let body = read_fixture(&path);
    let out = s
        .sanitize_plain(
            RawFetchedContent::from_string(body),
            ContentSource::File {
                path: path.display().to_string(),
            },
            ContentType::PlainText,
        )
        .unwrap();

    // The per-call nonce must not appear as a literal sentinel inside the
    // cleaned body, which would let an attacker close the wrap early.
    let nonce = &out.report.nonce;
    let start_marker = format!("<|sigil_external_start:{nonce}|>");
    let end_marker = format!("<|sigil_external_end:{nonce}|>");
    let body = wrap::extract_body(&out.text).expect("wrap must round-trip");
    assert!(
        !body.contains(&start_marker),
        "payload contained the per-call start marker — delimiter breakout!",
    );
    assert!(
        !body.contains(&end_marker),
        "payload contained the per-call end marker — delimiter breakout!",
    );
    // And a WRP-001 finding must be present because the payload contained
    // the wrapper prefix.
    assert!(out.report.findings.iter().any(|f| f.rule_id == "WRP-001"));
}

// ---- Benign corpus FP gate --------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FpBaseline {
    /// Lockstep with [`RISK_GATE_THRESHOLD`]. Persisted so a future
    /// threshold bump is a reviewable diff rather than a silent change.
    threshold: u8,
    /// Number of fetched (non-stub) fixtures contributing to the
    /// baseline. Persisted so a change in corpus size is visible.
    corpus_size: usize,
    /// Total number of fixtures that scored at or above `threshold`.
    /// CI asserts `measured_hits <= baseline_hits + 1`.
    baseline_hits: usize,
    /// Per-fixture score, in stable order. Lets a reviewer see which
    /// specific fixture moved when the baseline shifts.
    scores: BTreeMap<String, u8>,
}

#[test]
fn benign_corpus_fp_gate() {
    let s = sanitizer();
    let dir = fixtures_dir("benign");
    let mut scores: BTreeMap<String, u8> = BTreeMap::new();
    let mut skipped: Vec<String> = Vec::new();

    let entries = fs::read_dir(&dir).expect("benign fixtures dir must exist");
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
        {
            continue;
        }
        let body = read_fixture(&path);
        if body.trim_start().starts_with(FETCH_FAILED_SENTINEL) {
            skipped.push(name.to_owned());
            continue;
        }
        let out = s
            .sanitize_plain(
                RawFetchedContent::from_string(body),
                ContentSource::File {
                    path: path.display().to_string(),
                },
                ContentType::PlainText,
            )
            .unwrap_or_else(|e| panic!("sanitize {name} failed: {e}"));

        scores.insert(name.to_owned(), out.report.risk_score);
    }

    let measured_hits = scores
        .values()
        .filter(|s| **s >= RISK_GATE_THRESHOLD)
        .count();

    // PR3.6 retired the "zero FMT-001 hits on benign" hard gate — the
    // rule is now Info-level audit metadata and the pre-dispatch
    // reroute in `dispatch_sanitize` handles the real attacker case.
    // The absolute-delta baseline check (`measured_hits <= baseline_hits + 1`)
    // is the remaining regression detector.
    //
    // Compare measured hits to the locked baseline. First run bootstraps
    // the baseline file; subsequent runs enforce `measured <= baseline + 1`.
    let baseline_path = tests_dir().join("fp_baseline.json");
    let current_baseline = load_baseline(&baseline_path);

    if let Some(baseline) = current_baseline {
        assert_baseline_matches(&baseline, &scores, &skipped);
        let allowed = baseline.baseline_hits.saturating_add(1);
        assert!(
            measured_hits <= allowed,
            "benign FP rate regressed: measured_hits={measured_hits}, baseline_hits={}, allowed={allowed}\nskipped={skipped:?}\nper-fixture scores={scores:#?}",
            baseline.baseline_hits,
        );
    } else {
        let baseline = FpBaseline {
            threshold: RISK_GATE_THRESHOLD,
            corpus_size: scores.len(),
            baseline_hits: measured_hits,
            scores: scores.clone(),
        };
        write_baseline(&baseline_path, &baseline);
        // Fail loudly on first-run bootstrap so an operator notices the
        // baseline was just written and commits it deliberately.
        panic!(
            "fp_baseline.json did not exist — wrote initial baseline with {measured_hits} hits over {} fixtures. Review and commit.",
            scores.len(),
        );
    }
}

/// Assert that the locked baseline still matches the current run on:
/// - threshold (code/baseline contract drift)
/// - corpus size (fixture-set drift)
/// - fixture identity (delete+add swaps that keep the count constant)
///
/// Each failure mode panics with a message pointing the operator at the
/// specific drift and the remediation (re-run the baseline snapshot and
/// commit `fp_baseline.json` in the same change).
fn assert_baseline_matches(
    baseline: &FpBaseline,
    scores: &BTreeMap<String, u8>,
    skipped: &[String],
) {
    assert_eq!(
        baseline.threshold, RISK_GATE_THRESHOLD,
        "threshold drift between baseline ({}) and code ({RISK_GATE_THRESHOLD}) — update baseline in a reviewable commit",
        baseline.threshold,
    );
    assert_eq!(
        scores.len(),
        baseline.corpus_size,
        "benign corpus drift: baseline expected {expected} fixtures, this run scanned {actual}.\nskipped={skipped:?}\nIf this is intentional (fixture added or removed), re-run the baseline snapshot and commit `fp_baseline.json` in the same change.",
        expected = baseline.corpus_size,
        actual = scores.len(),
    );
    let baseline_keys: BTreeSet<&str> = baseline.scores.keys().map(String::as_str).collect();
    let current_keys: BTreeSet<&str> = scores.keys().map(String::as_str).collect();
    if baseline_keys != current_keys {
        let added: Vec<&str> = current_keys.difference(&baseline_keys).copied().collect();
        let removed: Vec<&str> = baseline_keys.difference(&current_keys).copied().collect();
        panic!(
            "benign corpus identity drift: added={added:?}, removed={removed:?}.\nIf intentional, re-run the baseline snapshot and commit `fp_baseline.json`.",
        );
    }
}

fn load_baseline(path: &Path) -> Option<FpBaseline> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_baseline(path: &Path, baseline: &FpBaseline) {
    let body = serde_json::to_string_pretty(baseline).expect("baseline must serialize");
    fs::write(path, body).expect("baseline must be writable");
}
