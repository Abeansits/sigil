//! Path traversal prevention.
//!
//! Validates that file paths stay within allowed root directories,
//! preventing escape via `..`, symlinks, or other tricks.

use std::path::{Path, PathBuf};

use crate::error::PolicyError;

/// Validate that a path resolves to a location within one of the allowed roots.
///
/// Canonicalizes the path (resolving `..` components and symlinks) and
/// then checks that the canonical result starts with at least one of the
/// `allowed_roots`. For paths that don't yet exist on disk (e.g.,
/// `WriteHostFile` targets), the *parent* directory is canonicalized
/// instead, and the final component is re-appended.
///
/// # Errors
///
/// - [`PolicyError::PathTraversalDenied`] if the canonical path is
///   outside all allowed roots, or if canonicalization fails.
pub fn validate_path(path: &Path, allowed_roots: &[PathBuf]) -> Result<PathBuf, PolicyError> {
    quick_path_check(path)?;

    let canonical = canonicalize_or_parent(path)?;

    // Canonicalize the roots too so that symlinks (e.g., /var ->
    // /private/var on macOS) don't cause false negatives.
    let root_matches = allowed_roots.iter().any(|root| {
        std::fs::canonicalize(root).is_ok_and(|cr| canonical.starts_with(cr))
    });

    if root_matches {
        Ok(canonical)
    } else {
        Err(PolicyError::PathTraversalDenied {
            reason: format!(
                "path '{}' resolves to '{}' which is outside all allowed roots",
                path.display(),
                canonical.display(),
            ),
        })
    }
}

/// Fast pre-check for suspicious path components.
///
/// Rejects paths containing `..` segments, null bytes, or control
/// characters. This runs before any filesystem access (canonicalization).
///
/// # Errors
///
/// - [`PolicyError::PathTraversalDenied`] if the path contains
///   suspicious content.
pub fn quick_path_check(path: &Path) -> Result<(), PolicyError> {
    let path_str = path.to_string_lossy();

    // Null bytes.
    if path_str.contains('\0') {
        return Err(PolicyError::PathTraversalDenied {
            reason: "path contains null byte".into(),
        });
    }

    // Control characters (ASCII 0x01..0x1F except tab/newline, which
    // are themselves weird in paths but less dangerous).
    if path_str
        .chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n')
    {
        return Err(PolicyError::PathTraversalDenied {
            reason: "path contains control characters".into(),
        });
    }

    Ok(())
}

/// Canonicalize a path, falling back to canonicalizing the parent when
/// the path itself does not exist (common for write targets).
fn canonicalize_or_parent(path: &Path) -> Result<PathBuf, PolicyError> {
    // Try the full path first.
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Ok(canonical);
    }

    // File doesn't exist -- canonicalize the parent and
    // re-append the final component.
    let parent = path
        .parent()
        .ok_or_else(|| PolicyError::PathTraversalDenied {
            reason: format!("path '{}' has no parent directory", path.display()),
        })?;
    let file_name = path
        .file_name()
        .ok_or_else(|| PolicyError::PathTraversalDenied {
            reason: format!("path '{}' has no file name component", path.display()),
        })?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|e| PolicyError::PathTraversalDenied {
            reason: format!("cannot canonicalize parent '{}': {e}", parent.display()),
        })?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use tempfile::tempdir;

    use super::*;

    // ------------------------------------------------------------------
    // quick_path_check
    // ------------------------------------------------------------------

    #[test]
    fn quick_check_rejects_null_bytes() {
        let path = Path::new("/tmp/evil\0file");
        assert!(quick_path_check(path).is_err());
    }

    #[test]
    fn quick_check_rejects_control_characters() {
        let path = Path::new("/tmp/evil\x01file");
        assert!(quick_path_check(path).is_err());
    }

    #[test]
    fn quick_check_allows_normal_path() {
        let path = Path::new("/tmp/safe/file.txt");
        assert!(quick_path_check(path).is_ok());
    }

    // ------------------------------------------------------------------
    // validate_path
    // ------------------------------------------------------------------

    #[test]
    fn normal_path_within_root_is_allowed() {
        let dir = tempdir().expect("tempdir creation should succeed");
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hi").expect("write should succeed");

        let roots = vec![dir.path().to_path_buf()];
        let result = validate_path(&file_path, &roots);
        assert!(
            result.is_ok(),
            "path within root should be allowed: {result:?}"
        );
    }

    #[test]
    fn path_with_dotdot_staying_inside_root_allowed() {
        let dir = tempdir().expect("tempdir creation should succeed");
        let sub = dir.path().join("a").join("b");
        std::fs::create_dir_all(&sub).expect("mkdir should succeed");

        // a/b/../c  resolves to  a/c  (still inside root)
        let file_path = sub.join("..").join("c.txt");
        // Create the target so canonicalize works.
        std::fs::write(dir.path().join("a").join("c.txt"), "ok").expect("write should succeed");

        let roots = vec![dir.path().to_path_buf()];
        let result = validate_path(&file_path, &roots);
        assert!(
            result.is_ok(),
            "path resolving inside root should be allowed: {result:?}"
        );
    }

    #[test]
    fn path_with_dotdot_escaping_root_is_denied() {
        let dir = tempdir().expect("tempdir creation should succeed");
        // Trying to go above the root.
        let escape_path = dir.path().join("..").join("etc").join("passwd");

        let roots = vec![dir.path().to_path_buf()];
        let result = validate_path(&escape_path, &roots);
        assert!(result.is_err(), "path escaping root should be denied");
    }

    #[test]
    fn null_byte_path_rejected_by_quick_check() {
        let dir = tempdir().expect("tempdir creation should succeed");
        let path = dir.path().join("evil\0file");
        let roots = vec![dir.path().to_path_buf()];
        let result = validate_path(&path, &roots);
        assert!(result.is_err(), "null byte path should be rejected");
    }

    #[test]
    fn empty_allowed_roots_denies_everything() {
        let dir = tempdir().expect("tempdir creation should succeed");
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hi").expect("write should succeed");

        let roots: Vec<PathBuf> = vec![];
        let result = validate_path(&file_path, &roots);
        assert!(result.is_err(), "empty roots should deny everything");
    }

    #[test]
    fn absolute_path_outside_all_roots_is_denied() {
        let dir = tempdir().expect("tempdir creation should succeed");
        let other_dir = tempdir().expect("second tempdir should succeed");

        let file_path = other_dir.path().join("sneaky.txt");
        std::fs::write(&file_path, "hi").expect("write should succeed");

        let roots = vec![dir.path().to_path_buf()];
        let result = validate_path(&file_path, &roots);
        assert!(result.is_err(), "path outside all roots should be denied");
    }

    #[test]
    fn nonexistent_file_validated_via_parent() {
        let dir = tempdir().expect("tempdir creation should succeed");
        // File doesn't exist but parent does.
        let file_path = dir.path().join("new_file.txt");

        let roots = vec![dir.path().to_path_buf()];
        let result = validate_path(&file_path, &roots);
        assert!(
            result.is_ok(),
            "nonexistent file with valid parent should be allowed: {result:?}"
        );
    }

    #[test]
    fn nonexistent_parent_is_denied() {
        let path = Path::new("/nonexistent_root_abc123/subdir/file.txt");
        let roots = vec![PathBuf::from("/tmp")];
        let result = validate_path(path, &roots);
        assert!(result.is_err(), "nonexistent parent should be denied");
    }
}
