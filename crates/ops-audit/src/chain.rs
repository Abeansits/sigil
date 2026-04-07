//! HMAC-chain logic for tamper-evident audit entries.
//!
//! Each entry carries a content hash (SHA-256 of the JSON payload),
//! a `prev_hash` linking to the prior entry, and an HMAC-SHA256 tag
//! computed over `content_hash || prev_hash`.

use hmac::{Hmac, Mac};
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
    pub event: ops_core::AuditEvent,
    pub content_hash: String,
    pub prev_hash: String,
    pub hmac: String,
}

/// Verify a sequence of chained entries, returning the first broken
/// link if any.
///
/// Checks three invariants per entry:
/// 1. The stored `content_hash` matches the SHA-256 of the
///    re-serialized event payload.
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
        let event_bytes = serde_json::to_vec(&entry.event).map_err(AuditError::Serialize)?;
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
    fn hmac_is_deterministic() {
        let key = b"test-secret-key";
        let ch = "abcdef1234567890abcdef1234567890\
                  abcdef1234567890abcdef1234567890";
        let ph = GENESIS_HASH;

        let h1 = compute_entry_hmac(key, ch, ph).expect("key should be valid");
        let h2 = compute_entry_hmac(key, ch, ph).expect("key should be valid");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "HMAC-SHA256 hex should be 64 chars");
    }

    #[test]
    fn hmac_differs_with_different_keys() {
        let ch = "abcdef1234567890abcdef1234567890\
                  abcdef1234567890abcdef1234567890";
        let ph = GENESIS_HASH;

        let h1 = compute_entry_hmac(b"key-one", ch, ph).expect("key should be valid");
        let h2 = compute_entry_hmac(b"key-two", ch, ph).expect("key should be valid");
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_detects_tampered_hmac() {
        let key = b"secret";
        let ch = content_hash(b"payload");
        let ph = GENESIS_HASH;

        let valid_hmac = compute_entry_hmac(key, &ch, ph).expect("key should be valid");
        let ok = verify_entry_hmac(key, &ch, ph, &valid_hmac).expect("key should be valid");
        assert!(ok);

        let bad = verify_entry_hmac(key, &ch, ph, "tampered_value").expect("key should be valid");
        assert!(!bad);
    }

    #[test]
    fn verify_chain_empty_is_ok() {
        let entries: Vec<ChainedEntry> = vec![];
        assert!(verify_chain(b"key", &entries).is_ok());
    }

    #[test]
    fn verify_chain_detects_tampered_entry() {
        let key = b"secret";
        let event = ops_core::AuditEvent {
            request_id: ops_core::RequestId::new(),
            timestamp: time::OffsetDateTime::now_utc(),
            action_summary: "test action".to_owned(),
            origin_summary: "test origin".to_owned(),
            decision: ops_core::PolicyDecision::Allow,
            session_id: None,
        };

        // Compute content hash from the actual serialized event.
        let event_bytes = serde_json::to_vec(&event).expect("serialization should succeed");
        let ch = content_hash(&event_bytes);
        let hmac_val = compute_entry_hmac(key, &ch, GENESIS_HASH).expect("key should be valid");

        let mut entry = ChainedEntry {
            event,
            content_hash: ch,
            prev_hash: GENESIS_HASH.to_owned(),
            hmac: hmac_val,
        };

        // Valid chain should pass.
        assert!(verify_chain(key, &[entry.clone()]).is_ok());

        // Tamper with the event payload -- content hash won't match.
        entry.event.action_summary = "TAMPERED".to_owned();
        assert!(verify_chain(key, &[entry]).is_err());
    }
}
