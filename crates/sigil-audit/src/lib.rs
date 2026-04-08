//! sigil-audit -- Append-only HMAC-chained JSONL audit trail.
//!
//! Every action in the system gets logged here with tamper detection.
//! Each entry carries a SHA-256 content hash of the event payload,
//! an HMAC-SHA256 tag linking it to the previous entry, and the raw
//! [`AuditEvent`] from `sigil-core`.
//!
//! # Architecture
//!
//! - **`chain`** -- HMAC computation and verification primitives.
//! - **`writer`** -- Async append-only JSONL writer with chain
//!   maintenance.
//! - **`verifier`** -- Read-only verification of an existing log
//!   file.
//! - **`error`** -- Domain-specific error types.

pub mod chain;
pub mod error;
pub mod verifier;
pub mod writer;

pub use error::AuditError;
pub use verifier::{VerifyResult, verify_log};
pub use writer::AuditLogWriter;

// ---------------------------------------------------------------------------
// Trait implementation: sigil_core::traits::AuditWriter
// ---------------------------------------------------------------------------

impl sigil_core::traits::AuditWriter for AuditLogWriter {
    async fn append(&self, event: &sigil_core::AuditEvent) -> Result<(), sigil_core::CoreError> {
        self.append(event).await.map_err(Into::into)
    }
}
