//! HMAC-chain logic for tamper-evident audit entries.
//!
//! Each entry carries a content hash (SHA-256 of the JSON payload),
//! a `prev_hash` linking to the prior entry, and an HMAC-SHA256 tag
//! computed over `content_hash || prev_hash`.

use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::AuditError;

type HmacSha256 = Hmac<Sha256>;

/// The genesis hash used as `prev_hash` for the first entry in a chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute the SHA-256 content hash of a JSON payload.
///
/// Returns the hash as a lowercase hex string.
pub fn content_hash(json_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(json_bytes);
    hex_encode(hasher.finalize())
}

/// Compute the HMAC-SHA256 tag for an audit entry.
///
/// The HMAC is computed over the concatenation of `content_hash`
/// and `prev_hash` (both as UTF-8 strings).
///
/// # Errors
///
/// Returns [`AuditError::KeyNotAvailable`] if the HMAC key is
/// rejected (should not happen with SHA-256 which accepts any
/// length).
pub fn compute_entry_hmac(
    key: &[u8],
    content_hash: &str,
    prev_hash: &str,
) -> Result<String, AuditError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AuditError::KeyNotAvailable)?;
    mac.update(content_hash.as_bytes());
    mac.update(prev_hash.as_bytes());
    Ok(hex_encode(mac.finalize().into_bytes()))
}

/// Verify that the HMAC tag on an entry is correct.
///
/// # Errors
///
/// Returns [`AuditError::KeyNotAvailable`] if the key is rejected.
pub fn verify_entry_hmac(
    key: &[u8],
    content_hash: &str,
    prev_hash: &str,
    expected_hmac: &str,
) -> Result<bool, AuditError> {
    let computed = compute_entry_hmac(key, content_hash, prev_hash)?;
    Ok(computed == expected_hmac)
}

/// Hex-encode bytes as a lowercase string.
fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    bytes.as_ref().iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// A single chained audit entry as stored in the JSONL file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainedEntry {
    pub event: sigil_core::AuditEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Map<String, Value>>,
    pub content_hash: String,
    pub prev_hash: String,
    pub hmac: String,
}

#[derive(Serialize)]
struct EntryPayload<'a> {
    event: &'a sigil_core::AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<&'a Map<String, Value>>,
}

/// Serialize the content-hashed payload for a chained entry.
///
/// # Errors
///
/// Returns [`AuditError::Serialize`] if the payload cannot be encoded
/// as JSON.
pub fn payload_bytes(
    event: &sigil_core::AuditEvent,
    fields: Option<&Map<String, Value>>,
) -> Result<Vec<u8>, AuditError> {
    match fields {
        Some(fields) => serde_json::to_vec(&EntryPayload {
            event,
            fields: Some(fields),
        })
        .map_err(AuditError::Serialize),
        None => serde_json::to_vec(event).map_err(AuditError::Serialize),
    }
}

/// Verify a sequence of chained entries, returning the first broken
/// link if any.
///
/// Checks three invariants per entry:
/// 1. The stored `content_hash` matches the SHA-256 of the re-serialized event payload.
/// 2. The `prev_hash` equals the previous entry's HMAC (or genesis).
/// 3. The HMAC tag is correct for the content and prev hashes.
///
/// # Errors
///
/// - [`AuditError::ChainBroken`] if any invariant is violated.
/// - [`AuditError::KeyNotAvailable`] if the HMAC key is rejected.
/// - [`AuditError::Serialize`] if the event cannot be re-serialized.
pub fn verify_chain(key: &[u8], entries: &[ChainedEntry]) -> Result<(), AuditError> {
    let mut expected_prev = GENESIS_HASH.to_owned();

    for entry in entries {
        let event_id = entry.event.request_id.to_string();

        // 1. Verify content hash matches the event payload.
        let event_bytes = payload_bytes(&entry.event, entry.fields.as_ref())?;
        let recomputed_hash = content_hash(&event_bytes);
        if recomputed_hash != entry.content_hash {
            return Err(AuditError::ChainBroken {
                event_id,
                expected: recomputed_hash,
                actual: entry.content_hash.clone(),
            });
        }

        // 2. Verify prev_hash linkage.
        if entry.prev_hash != expected_prev {
            return Err(AuditError::ChainBroken {
                event_id,
                expected: expected_prev,
                actual: entry.prev_hash.clone(),
            });
        }

        // 3. Verify HMAC tag.
        let hmac_ok = verify_entry_hmac(key, &entry.content_hash, &entry.prev_hash, &entry.hmac)?;

        if !hmac_ok {
            let correct = compute_entry_hmac(key, &entry.content_hash, &entry.prev_hash)?;
            return Err(AuditError::ChainBroken {
                event_id,
                expected: correct,
                actual: entry.hmac.clone(),
            });
        }

        expected_prev.clone_from(&entry.hmac);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn content_hash_is_deterministic() {
        let data = br#"{"hello":"world"}"#;
        let h1 = content_hash(data);
        let h2 = content_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "SHA-256 hex should be 64 chars");
    }

    #[test]
    fn hmac_is_deterministic() -> Result<(), Box<dyn Error>> {
        let key = b"test-secret-key";
        let ch = "abcdef1234567890abcdef1234567890\
                  abcdef1234567890abcdef1234567890";
        let ph = GENESIS_HASH;

        let h1 = compute_entry_hmac(key, ch, ph)?;
        let h2 = compute_entry_hmac(key, ch, ph)?;
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "HMAC-SHA256 hex should be 64 chars");
        Ok(())
    }

    #[test]
    fn hmac_differs_with_different_keys() -> Result<(), Box<dyn Error>> {
        let ch = "abcdef1234567890abcdef1234567890\
                  abcdef1234567890abcdef1234567890";
        let ph = GENESIS_HASH;

        let h1 = compute_entry_hmac(b"key-one", ch, ph)?;
        let h2 = compute_entry_hmac(b"key-two", ch, ph)?;
        assert_ne!(h1, h2);
        Ok(())
    }

    #[test]
    fn verify_detects_tampered_hmac() -> Result<(), Box<dyn Error>> {
        let key = b"secret";
        let ch = content_hash(b"payload");
        let ph = GENESIS_HASH;

        let valid_hmac = compute_entry_hmac(key, &ch, ph)?;
        let ok = verify_entry_hmac(key, &ch, ph, &valid_hmac)?;
        assert!(ok);

        let bad = verify_entry_hmac(key, &ch, ph, "tampered_value")?;
        assert!(!bad);
        Ok(())
    }

    #[test]
    fn verify_chain_empty_is_ok() {
        let entries: Vec<ChainedEntry> = vec![];
        assert!(verify_chain(b"key", &entries).is_ok());
    }

    #[test]
    fn verify_chain_detects_tampered_entry() -> Result<(), Box<dyn Error>> {
        let key = b"secret";
        let event = sigil_core::AuditEvent {
            request_id: sigil_core::RequestId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            action_summary: "test action".to_owned(),
            origin_summary: "test origin".to_owned(),
            decision: sigil_core::PolicyDecision::Allow,
            session_id: None,
            sanitize_report: None,
        };

        // Compute content hash from the actual serialized event.
        let event_bytes = payload_bytes(&event, None)?;
        let ch = content_hash(&event_bytes);
        let hmac_val = compute_entry_hmac(key, &ch, GENESIS_HASH)?;

        let mut entry = ChainedEntry {
            event,
            fields: None,
            content_hash: ch,
            prev_hash: GENESIS_HASH.to_owned(),
            hmac: hmac_val,
        };

        // Valid chain should pass.
        assert!(verify_chain(key, &[entry.clone()]).is_ok());

        // Tamper with the event payload -- content hash won't match.
        entry.event.action_summary = "TAMPERED".to_owned();
        assert!(verify_chain(key, &[entry]).is_err());
        Ok(())
    }

    #[test]
    fn payload_bytes_without_fields_matches_legacy_event_hash() -> Result<(), Box<dyn Error>> {
        let event = sigil_core::AuditEvent {
            request_id: sigil_core::RequestId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            action_summary: "legacy event".to_owned(),
            origin_summary: "legacy origin".to_owned(),
            decision: sigil_core::PolicyDecision::Allow,
            session_id: None,
            sanitize_report: None,
        };

        let legacy = serde_json::to_vec(&event)?;
        let compat = payload_bytes(&event, None)?;

        assert_eq!(compat, legacy);
        assert_eq!(content_hash(&compat), content_hash(&legacy));
        Ok(())
    }

    #[test]
    fn verify_chain_accepts_mixed_legacy_and_structured_entries() -> Result<(), Box<dyn Error>> {
        let key = b"mixed-chain-key";
        let first = sigil_core::AuditEvent {
            request_id: sigil_core::RequestId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            action_summary: "legacy event".to_owned(),
            origin_summary: "legacy origin".to_owned(),
            decision: sigil_core::PolicyDecision::Allow,
            session_id: None,
            sanitize_report: None,
        };
        let second = sigil_core::AuditEvent {
            request_id: sigil_core::RequestId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            action_summary: "bridge.reply_sent".to_owned(),
            origin_summary: "BridgeSlack { user_id: U_TEST }".to_owned(),
            decision: sigil_core::PolicyDecision::Allow,
            session_id: None,
            sanitize_report: None,
        };
        let second_fields = Map::from_iter([
            ("text_len".to_owned(), Value::from(42_u64)),
            ("truncated".to_owned(), Value::from(false)),
            ("normalized_len".to_owned(), Value::from(42_u64)),
            (
                "target_origin".to_owned(),
                Value::from("BridgeSlack { user_id: U_TEST }"),
            ),
        ]);

        let first_bytes = payload_bytes(&first, None)?;
        let first_hash = content_hash(&first_bytes);
        let first_hmac = compute_entry_hmac(key, &first_hash, GENESIS_HASH)?;
        let second_bytes = payload_bytes(&second, Some(&second_fields))?;
        let second_hash = content_hash(&second_bytes);
        let second_hmac = compute_entry_hmac(key, &second_hash, &first_hmac)?;

        let entries = vec![
            ChainedEntry {
                event: first,
                fields: None,
                content_hash: first_hash,
                prev_hash: GENESIS_HASH.to_owned(),
                hmac: first_hmac.clone(),
            },
            ChainedEntry {
                event: second,
                fields: Some(second_fields),
                content_hash: second_hash,
                prev_hash: first_hmac,
                hmac: second_hmac,
            },
        ];

        verify_chain(key, &entries)?;
        Ok(())
    }
}

#[cfg(test)]
mod proptest_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use proptest::prelude::*;
    use sigil_core::PolicyDecision;

    use super::*;

    fn arb_decision() -> impl Strategy<Value = PolicyDecision> {
        prop_oneof![
            Just(PolicyDecision::Allow),
            "[a-z ]{1,30}".prop_map(|reason| PolicyDecision::Deny { reason }),
            "[a-z ]{1,30}".prop_map(|desc| PolicyDecision::NeedsApproval { description: desc }),
        ]
    }

    fn arb_audit_event() -> impl Strategy<Value = sigil_core::AuditEvent> {
        ("[a-zA-Z ]{1,30}", "[a-zA-Z ]{1,30}", arb_decision()).prop_map(
            |(action_summary, origin_summary, decision)| sigil_core::AuditEvent {
                request_id: sigil_core::RequestId::new(),
                timestamp: time::OffsetDateTime::now_utc(),
                action_summary,
                origin_summary,
                decision,
                session_id: None,
                sanitize_report: None,
            },
        )
    }

    /// Build a valid HMAC chain from a sequence of events.
    fn build_chain(key: &[u8], events: &[sigil_core::AuditEvent]) -> Vec<ChainedEntry> {
        let mut entries = Vec::with_capacity(events.len());
        let mut prev = GENESIS_HASH.to_owned();

        for event in events {
            let event_bytes = payload_bytes(event, None).expect("serialize event");
            let ch = content_hash(&event_bytes);
            let hmac_val = compute_entry_hmac(key, &ch, &prev).expect("compute hmac");
            entries.push(ChainedEntry {
                event: event.clone(),
                fields: None,
                content_hash: ch,
                prev_hash: prev.clone(),
                hmac: hmac_val.clone(),
            });
            prev = hmac_val;
        }

        entries
    }

    proptest! {
        /// A correctly built chain always verifies.
        #[test]
        fn valid_chain_verifies(
            events in proptest::collection::vec(arb_audit_event(), 1..20),
            key in proptest::collection::vec(any::<u8>(), 16..64),
        ) {
            let entries = build_chain(&key, &events);
            prop_assert!(
                verify_chain(&key, &entries).is_ok(),
                "valid chain should verify"
            );
        }

        /// Tampering with any event's action_summary breaks the chain.
        #[test]
        fn tampered_event_breaks_chain(
            events in proptest::collection::vec(arb_audit_event(), 1..10),
            tamper_offset in any::<usize>(),
        ) {
            let key = b"proptest-secret";
            let mut entries = build_chain(key, &events);
            let idx = tamper_offset % entries.len();
            entries[idx].event.action_summary = "TAMPERED".to_owned();
            prop_assert!(
                verify_chain(key, &entries).is_err(),
                "tampered chain at index {idx} should fail verification"
            );
        }

        /// Tampering with an entry's prev_hash breaks the chain.
        #[test]
        fn tampered_prev_hash_breaks_chain(
            events in proptest::collection::vec(arb_audit_event(), 2..10),
            tamper_offset in any::<usize>(),
        ) {
            let key = b"proptest-secret";
            let mut entries = build_chain(key, &events);
            // Tamper with a non-first entry's prev_hash (first entry
            // would need genesis hash tampering which is a different case).
            let idx = 1 + (tamper_offset % (entries.len() - 1));
            entries[idx].prev_hash = "deadbeef".repeat(8);
            prop_assert!(
                verify_chain(key, &entries).is_err(),
                "tampered prev_hash at index {idx} should fail"
            );
        }

        /// Tampering with an entry's HMAC tag breaks the chain.
        #[test]
        fn tampered_hmac_breaks_chain(
            events in proptest::collection::vec(arb_audit_event(), 1..10),
            tamper_offset in any::<usize>(),
        ) {
            let key = b"proptest-secret";
            let mut entries = build_chain(key, &events);
            let idx = tamper_offset % entries.len();
            entries[idx].hmac = "cafebabe".repeat(8);
            prop_assert!(
                verify_chain(key, &entries).is_err(),
                "tampered HMAC at index {idx} should fail"
            );
        }

        /// Content hash is deterministic: same bytes always produce
        /// the same hash.
        #[test]
        fn content_hash_deterministic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let h1 = content_hash(&data);
            let h2 = content_hash(&data);
            prop_assert_eq!(h1, h2);
        }

        /// HMAC is deterministic: same key + inputs always produce the
        /// same tag.
        #[test]
        fn hmac_deterministic(
            key in proptest::collection::vec(any::<u8>(), 16..64),
            ch in "[0-9a-f]{64}",
            ph in "[0-9a-f]{64}",
        ) {
            let h1 = compute_entry_hmac(&key, &ch, &ph).expect("hmac");
            let h2 = compute_entry_hmac(&key, &ch, &ph).expect("hmac");
            prop_assert_eq!(h1, h2);
        }
    }
}
