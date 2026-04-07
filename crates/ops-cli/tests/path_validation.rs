//! Path validation security integration tests.
//!
//! Exercises the path traversal prevention logic from ops-policy
//! using real filesystem paths in temp directories.

use std::path::{Path, PathBuf};

use ops_policy::paths::{quick_path_check, validate_path};

// ------------------------------------------------------------------
// Traversal attack prevention
// ------------------------------------------------------------------

#[test]
fn path_traversal_attack_with_dotdot_is_blocked() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let allowed_root = dir.path().to_path_buf();

    // Try to escape via ../../../etc/passwd.
    let attack_path = dir
        .path()
        .join("..")
        .join("..")
        .join("..")
        .join("etc")
        .join("passwd");

    let result = validate_path(&attack_path, &[allowed_root]);
    assert!(result.is_err(), "traversal attack should be denied");
}

#[test]
fn path_traversal_with_single_dotdot_is_blocked() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let allowed_root = dir.path().to_path_buf();

    let attack_path = dir.path().join("..").join("etc").join("passwd");

    let result = validate_path(&attack_path, &[allowed_root]);
    assert!(result.is_err(), "single .. escape should be denied");
}

#[test]
fn dotdot_resolving_inside_root_is_allowed() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let sub = dir.path().join("a").join("b");
    std::fs::create_dir_all(&sub).expect("mkdir should succeed");

    // a/b/../c.txt resolves to a/c.txt (still inside root).
    let target = dir.path().join("a").join("c.txt");
    std::fs::write(&target, "ok").expect("write should succeed");

    let path_with_dotdot = sub.join("..").join("c.txt");
    let result = validate_path(&path_with_dotdot, &[dir.path().to_path_buf()]);
    assert!(
        result.is_ok(),
        "path resolving inside root should be allowed: {result:?}"
    );
}

// ------------------------------------------------------------------
// Null byte and control character injection
// ------------------------------------------------------------------

#[test]
fn null_byte_in_path_is_rejected() {
    let path = Path::new("/tmp/evil\0file");
    assert!(
        quick_path_check(path).is_err(),
        "null byte path should be rejected"
    );
}

#[test]
fn control_characters_in_path_are_rejected() {
    let path = Path::new("/tmp/evil\x01file");
    assert!(
        quick_path_check(path).is_err(),
        "control char path should be rejected"
    );
}

#[test]
fn bell_character_in_path_is_rejected() {
    let path = Path::new("/tmp/evil\x07file");
    assert!(
        quick_path_check(path).is_err(),
        "bell character path should be rejected"
    );
}

// ------------------------------------------------------------------
// Empty and nonexistent root handling
// ------------------------------------------------------------------

#[test]
fn empty_allowed_roots_denies_everything() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "content").expect("write should succeed");

    let roots: Vec<PathBuf> = vec![];
    let result = validate_path(&file_path, &roots);
    assert!(result.is_err(), "empty roots should deny all paths");
}

#[test]
fn path_outside_all_roots_is_denied() {
    let root_dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let other_dir = tempfile::tempdir().expect("second tempdir should succeed");

    let file_path = other_dir.path().join("sneaky.txt");
    std::fs::write(&file_path, "hi").expect("write should succeed");

    let result = validate_path(&file_path, &[root_dir.path().to_path_buf()]);
    assert!(result.is_err(), "path outside all roots should be denied");
}

// ------------------------------------------------------------------
// Nonexistent file with valid parent
// ------------------------------------------------------------------

#[test]
fn nonexistent_file_within_valid_root_is_allowed() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    // File doesn't exist yet, but parent directory does.
    let new_file = dir.path().join("will-be-created.txt");

    let result = validate_path(&new_file, &[dir.path().to_path_buf()]);
    assert!(
        result.is_ok(),
        "nonexistent file with valid parent should be allowed: {result:?}"
    );
}

#[test]
fn nonexistent_parent_directory_is_denied() {
    let path = Path::new("/nonexistent_root_xyz789/subdir/file.txt");
    let roots = vec![PathBuf::from("/tmp")];

    let result = validate_path(path, &roots);
    assert!(result.is_err(), "nonexistent parent should be denied");
}

// ------------------------------------------------------------------
// Multiple allowed roots
// ------------------------------------------------------------------

#[test]
fn path_valid_in_second_root_is_allowed() {
    let root_a = tempfile::tempdir().expect("tempdir a should succeed");
    let root_b = tempfile::tempdir().expect("tempdir b should succeed");

    let file_path = root_b.path().join("allowed.txt");
    std::fs::write(&file_path, "ok").expect("write should succeed");

    let roots = vec![root_a.path().to_path_buf(), root_b.path().to_path_buf()];

    let result = validate_path(&file_path, &roots);
    assert!(
        result.is_ok(),
        "path in second root should be allowed: {result:?}"
    );
}

#[test]
fn deeply_nested_path_within_root_is_allowed() {
    let dir = tempfile::tempdir().expect("tempdir creation should succeed");
    let deep = dir.path().join("a").join("b").join("c").join("d");
    std::fs::create_dir_all(&deep).expect("mkdir should succeed");

    let file_path = deep.join("deep.txt");
    std::fs::write(&file_path, "deep content").expect("write should succeed");

    let result = validate_path(&file_path, &[dir.path().to_path_buf()]);
    assert!(
        result.is_ok(),
        "deeply nested path should be allowed: {result:?}"
    );
}
