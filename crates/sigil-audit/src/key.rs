//! Audit HMAC key loading and Keychain management.
//!
//! Resolution order:
//! 1. `SIGIL_AUDIT_KEY` environment variable (highest — used by CI/tests).
//! 2. macOS Keychain entry under service `"sigil"`, account `"audit-hmac"`
//!    (production default on macOS).
//! 3. Built-in development key, only when **all** of the following hold
//!    (warns loudly when used):
//!      * the binary was built with `debug_assertions` (i.e. not a
//!        release build), and
//!      * `SIGIL_DEV_AUDIT_KEY=1` is set in the environment.
//!
//!    Release builds **never** activate the dev fallback, so an env var
//!    leaking into a production process unit cannot silently downgrade
//!    the audit key.
//!
//! On non-macOS targets the Keychain step is a no-op and the dev
//! fallback is the only available source (still subject to the rules
//! above).

use crate::AuditError;

/// Keychain service name for the HMAC key entry.
pub const KEYCHAIN_SERVICE: &str = "sigil";

/// Keychain account name for the HMAC key entry.
pub const KEYCHAIN_ACCOUNT: &str = "audit-hmac";

/// Environment variable that overrides the Keychain.
pub const ENV_KEY: &str = "SIGIL_AUDIT_KEY";

/// Environment variable that opts into the built-in dev key.
pub const ENV_DEV_OPT_IN: &str = "SIGIL_DEV_AUDIT_KEY";

/// Built-in development key, padded to [`GENERATED_KEY_LEN`]. Only used
/// when `SIGIL_DEV_AUDIT_KEY=1` is set in a `debug_assertions` build.
const DEV_KEY: &[u8; GENERATED_KEY_LEN] = b"sigil-dev-audit-key-CHANGE-MExxx";

/// Length of newly generated keys, in bytes.
pub const GENERATED_KEY_LEN: usize = 32;

/// Where the loaded key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// Loaded from the `SIGIL_AUDIT_KEY` env var.
    Env,
    /// Loaded from the macOS Keychain.
    Keychain,
    /// Loaded from the built-in dev fallback (opt-in).
    Dev,
}

impl KeySource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Env => "env:SIGIL_AUDIT_KEY",
            Self::Keychain => "keychain:sigil/audit-hmac",
            Self::Dev => "dev-fallback",
        }
    }
}

/// A key loaded from one of the configured sources.
pub struct LoadedKey {
    pub bytes: Vec<u8>,
    pub source: KeySource,
}

/// Resolve the audit HMAC key according to the documented priority order.
///
/// # Errors
///
/// - [`AuditError::KeyNotAvailable`] if no source produces a key.
/// - [`AuditError::InvalidEnvKey`] if `SIGIL_AUDIT_KEY` is set but is
///   non-UTF-8 or contains only whitespace.
/// - [`AuditError::Keychain`] if the Keychain lookup fails for any
///   reason other than the entry being absent.
pub fn load_audit_key() -> Result<LoadedKey, AuditError> {
    if let Some(bytes) = env_key()? {
        return Ok(LoadedKey {
            bytes,
            source: KeySource::Env,
        });
    }

    match keychain::read() {
        Ok(Some(bytes)) => {
            return Ok(LoadedKey {
                bytes,
                source: KeySource::Keychain,
            });
        }
        Ok(None) => {} // entry missing — fall through
        Err(e) => return Err(AuditError::Keychain(e.to_string())),
    }

    if dev_fallback_allowed() {
        tracing::warn!(
            source = "dev-fallback",
            "Using built-in DEV audit HMAC key (SIGIL_DEV_AUDIT_KEY=1, debug build). \
             This key is public; do NOT use in production."
        );
        return Ok(LoadedKey {
            bytes: DEV_KEY.to_vec(),
            source: KeySource::Dev,
        });
    }

    Err(AuditError::KeyNotAvailable)
}

/// Generate a fresh 32-byte audit key from the OS CSPRNG.
///
/// # Errors
///
/// Returns [`AuditError::Random`] if the system random source fails.
pub fn generate_key() -> Result<Vec<u8>, AuditError> {
    let mut buf = vec![0_u8; GENERATED_KEY_LEN];
    getrandom::getrandom(&mut buf).map_err(|e| AuditError::Random(e.to_string()))?;
    Ok(buf)
}

fn env_key() -> Result<Option<Vec<u8>>, AuditError> {
    match std::env::var(ENV_KEY) {
        Ok(s) => {
            if s.trim().is_empty() {
                return Err(AuditError::InvalidEnvKey {
                    reason: "value is empty or whitespace-only".to_owned(),
                });
            }
            Ok(Some(s.into_bytes()))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(AuditError::InvalidEnvKey {
            reason: "value is not valid UTF-8".to_owned(),
        }),
    }
}

/// Whether the dev fallback may activate. False in release builds — even
/// with the env var set — so that a leaked `SIGIL_DEV_AUDIT_KEY=1` cannot
/// silently downgrade a production process.
fn dev_fallback_allowed() -> bool {
    cfg!(debug_assertions) && std::env::var(ENV_DEV_OPT_IN).is_ok_and(|v| v == "1")
}

// ---------------------------------------------------------------------------
// Keychain backend
// ---------------------------------------------------------------------------

/// Errors from the Keychain backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeychainError {
    #[error("keychain entry not found")]
    NotFound,
    #[error("keychain backend not supported on this platform")]
    Unsupported,
    #[error("keychain operation failed: {0}")]
    Backend(String),
}

#[cfg(target_os = "macos")]
pub mod keychain {
    //! macOS Keychain backend using the `security-framework` crate.

    use security_framework::base::Error as SfError;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    use super::{KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE, KeychainError};

    /// `errSecItemNotFound` — the canonical "no such item" status code.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

    /// Read the audit key from the Keychain.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` when the entry simply does not exist, and
    /// [`KeychainError::Backend`] for any other failure.
    pub fn read() -> Result<Option<Vec<u8>>, KeychainError> {
        match get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if is_not_found(e) => Ok(None),
            Err(e) => Err(KeychainError::Backend(e.to_string())),
        }
    }

    /// Write (or replace) the audit key in the Keychain.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::Backend`] if the underlying call fails.
    pub fn write(key: &[u8]) -> Result<(), KeychainError> {
        set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key)
            .map_err(|e| KeychainError::Backend(e.to_string()))
    }

    /// Delete the audit key from the Keychain.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists,
    /// [`KeychainError::Backend`] for any other failure.
    pub fn delete() -> Result<(), KeychainError> {
        match delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
            Ok(()) => Ok(()),
            Err(e) if is_not_found(e) => Err(KeychainError::NotFound),
            Err(e) => Err(KeychainError::Backend(e.to_string())),
        }
    }

    fn is_not_found(e: SfError) -> bool {
        e.code() == ERR_SEC_ITEM_NOT_FOUND
    }
}

#[cfg(not(target_os = "macos"))]
pub mod keychain {
    //! Stub backend for non-macOS targets.

    use super::KeychainError;

    /// Stub: always reports "no key stored" on non-macOS targets.
    ///
    /// # Errors
    ///
    /// This stub never errors; the real backend's error signature is
    /// preserved so callers compile unchanged on Linux / CI.
    pub fn read() -> Result<Option<Vec<u8>>, KeychainError> {
        Ok(None)
    }

    /// Stub: non-macOS targets cannot persist to a system keychain.
    ///
    /// # Errors
    ///
    /// Always returns [`KeychainError::Unsupported`].
    pub fn write(_key: &[u8]) -> Result<(), KeychainError> {
        Err(KeychainError::Unsupported)
    }

    /// Stub: non-macOS targets have nothing to delete.
    ///
    /// # Errors
    ///
    /// Always returns [`KeychainError::Unsupported`].
    pub fn delete() -> Result<(), KeychainError> {
        Err(KeychainError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn generate_produces_32_bytes() {
        let k = generate_key().expect("generate should succeed");
        assert_eq!(k.len(), GENERATED_KEY_LEN);
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = generate_key().expect("generate should succeed");
        let b = generate_key().expect("generate should succeed");
        assert_ne!(a, b, "two random keys should not collide");
    }

    #[test]
    fn key_source_label_is_stable() {
        assert_eq!(KeySource::Env.label(), "env:SIGIL_AUDIT_KEY");
        assert_eq!(KeySource::Keychain.label(), "keychain:sigil/audit-hmac");
        assert_eq!(KeySource::Dev.label(), "dev-fallback");
    }

    #[test]
    fn dev_key_matches_generated_length() {
        assert_eq!(DEV_KEY.len(), GENERATED_KEY_LEN);
    }
}
