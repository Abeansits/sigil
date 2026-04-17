//! Git worktree management for agent sessions.
//!
//! Each session can optionally run in its own git worktree, giving it an
//! isolated working copy of the repo. Branch names containing `/` are
//! sanitised to `-` for the worktree directory name.

use std::path::{Path, PathBuf};

use tokio::process::Command;
use tracing::{debug, warn};

use crate::error::RuntimeError;

/// Information about a single git worktree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorktreeInfo {
    pub path: PathBuf,
    pub branch: String,
    pub is_bare: bool,
}

/// Stateless helper for creating, finishing, and listing git worktrees.
pub struct WorktreeManager;

impl WorktreeManager {
    /// Create a git worktree for a session.
    ///
    /// Runs `git worktree add -b {branch} {worktree_path}` inside `repo`.
    /// The worktree directory is placed at `{repo}/.worktrees/{sanitised}`.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the git command fails.
    pub async fn create(
        repo: &Path,
        branch: &str,
        worktree_path: &Path,
    ) -> Result<(), RuntimeError> {
        let wt_str = worktree_path
            .to_str()
            .ok_or_else(|| RuntimeError::GitCommand {
                command: "worktree add".to_owned(),
                stderr: "worktree path is not valid UTF-8".to_owned(),
            })?;

        let output = Command::new("git")
            .args(["worktree", "add", "-b", branch, wt_str])
            .current_dir(repo)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(RuntimeError::GitCommand {
                command: format!("git worktree add -b {branch} {wt_str}"),
                stderr,
            });
        }

        debug!(repo = %repo.display(), branch, worktree = %worktree_path.display(), "created worktree");
        Ok(())
    }

    /// Finish a worktree: optionally merge, then remove, then delete branch.
    ///
    /// When `merge` is `true`, runs `git merge {branch}` from the main
    /// worktree before removing. Always finishes with
    /// `git worktree remove {worktree_path}` followed by
    /// `git branch -d {branch}` to clean up the local branch.
    ///
    /// Branch deletion uses `-d` (not `-D`) so it only succeeds if the
    /// branch is fully merged. If deletion fails (e.g. unmerged changes),
    /// a warning is logged but the overall operation still succeeds.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if merging or worktree removal fails.
    /// Branch deletion failure is non-fatal.
    pub async fn finish(
        repo: &Path,
        branch: &str,
        worktree_path: &Path,
        merge: bool,
    ) -> Result<(), RuntimeError> {
        if merge {
            let output = Command::new("git")
                .args(["merge", branch])
                .current_dir(repo)
                .output()
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                return Err(RuntimeError::GitCommand {
                    command: format!("git merge {branch}"),
                    stderr,
                });
            }

            debug!(repo = %repo.display(), branch, "merged worktree branch");
        }

        let wt_str = worktree_path
            .to_str()
            .ok_or_else(|| RuntimeError::GitCommand {
                command: "worktree remove".to_owned(),
                stderr: "worktree path is not valid UTF-8".to_owned(),
            })?;

        let output = Command::new("git")
            .args(["worktree", "remove", wt_str])
            .current_dir(repo)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(RuntimeError::GitCommand {
                command: format!("git worktree remove {wt_str}"),
                stderr,
            });
        }

        debug!(repo = %repo.display(), worktree = %worktree_path.display(), "removed worktree");

        // Delete the local branch. Use -d (safe delete) so it only
        // succeeds if the branch is fully merged. Failure is non-fatal.
        delete_branch_safe(repo, branch).await;

        Ok(())
    }

    /// List active worktrees for a repository.
    ///
    /// Parses `git worktree list --porcelain` output.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the git command fails.
    pub async fn list(repo: &Path) -> Result<Vec<WorktreeInfo>, RuntimeError> {
        let output = Command::new("git")
            .args(["worktree", "list", "--porcelain"])
            .current_dir(repo)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(RuntimeError::GitCommand {
                command: "git worktree list --porcelain".to_owned(),
                stderr,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_porcelain(&stdout))
    }

    /// Build the standard worktree path for a branch.
    ///
    /// Returns `{repo}/.worktrees/{sanitised}` where `/` in the branch
    /// name is replaced with `-`.
    #[must_use]
    pub fn worktree_path(repo: &Path, branch: &str) -> PathBuf {
        let sanitised = branch.replace('/', "-");
        repo.join(".worktrees").join(sanitised)
    }
}

/// Attempt to delete a local branch with `git branch -d`.
///
/// Uses `-d` (not `-D`) so unmerged branches are preserved. Failure is
/// logged as a warning and never propagated.
async fn delete_branch_safe(repo: &Path, branch: &str) {
    let result = Command::new("git")
        .args(["branch", "-d", branch])
        .current_dir(repo)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            debug!(repo = %repo.display(), branch, "deleted branch after worktree finish");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                repo = %repo.display(),
                branch,
                stderr = %stderr.trim(),
                "branch deletion failed (likely unmerged) — leaving branch intact",
            );
        }
        Err(e) => {
            warn!(
                repo = %repo.display(),
                branch,
                error = %e,
                "failed to run git branch -d — leaving branch intact",
            );
        }
    }
}

/// Parse `git worktree list --porcelain` output into `WorktreeInfo` entries.
///
/// Porcelain format: blocks separated by blank lines, each block has
/// lines like `worktree /path`, `branch refs/heads/name`, and optionally
/// `bare`.
fn parse_porcelain(raw: &str) -> Vec<WorktreeInfo> {
    let mut results = Vec::new();
    let mut path: Option<PathBuf> = None;
    let mut branch = String::new();
    let mut is_bare = false;

    for line in raw.lines() {
        if line.is_empty() {
            // End of a block — flush if we have a path.
            if let Some(p) = path.take() {
                results.push(WorktreeInfo {
                    path: p,
                    branch: branch.clone(),
                    is_bare,
                });
            }
            branch.clear();
            is_bare = false;
            continue;
        }

        if let Some(rest) = line.strip_prefix("worktree ") {
            path = Some(PathBuf::from(rest));
        } else if let Some(rest) = line.strip_prefix("branch ") {
            // Strip the refs/heads/ prefix if present.
            rest.strip_prefix("refs/heads/")
                .unwrap_or(rest)
                .clone_into(&mut branch);
        } else if line == "bare" {
            is_bare = true;
        }
    }

    // Flush the last block if the output does not end with a blank line.
    if let Some(p) = path {
        results.push(WorktreeInfo {
            path: p,
            branch,
            is_bare,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::print_stderr)]

    use super::*;

    // -----------------------------------------------------------------------
    // parse_porcelain
    // -----------------------------------------------------------------------

    #[test]
    fn parse_porcelain_with_two_worktrees_returns_both() {
        let raw = "\
worktree /home/user/project
branch refs/heads/main
HEAD abc1234

worktree /home/user/project/.worktrees/feature-foo
branch refs/heads/feature/foo
HEAD def5678

";
        let entries = parse_porcelain(raw);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, PathBuf::from("/home/user/project"));
        assert_eq!(entries[0].branch, "main");
        assert!(!entries[0].is_bare);
        assert_eq!(
            entries[1].path,
            PathBuf::from("/home/user/project/.worktrees/feature-foo"),
        );
        assert_eq!(entries[1].branch, "feature/foo");
        assert!(!entries[1].is_bare);
    }

    #[test]
    fn parse_porcelain_with_bare_worktree_sets_flag() {
        let raw = "\
worktree /home/user/bare-repo
bare
HEAD abc1234

";
        let entries = parse_porcelain(raw);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_bare);
        assert!(entries[0].branch.is_empty());
    }

    #[test]
    fn parse_porcelain_empty_input_returns_empty() {
        let entries = parse_porcelain("");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_porcelain_no_trailing_newline_flushes_last_block() {
        let raw = "worktree /tmp/repo\nbranch refs/heads/main";
        let entries = parse_porcelain(raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, PathBuf::from("/tmp/repo"));
        assert_eq!(entries[0].branch, "main");
    }

    // -----------------------------------------------------------------------
    // worktree_path
    // -----------------------------------------------------------------------

    #[test]
    fn worktree_path_sanitises_slashes() {
        let repo = Path::new("/home/user/project");
        let result = WorktreeManager::worktree_path(repo, "feature/auth/login");
        assert_eq!(
            result,
            PathBuf::from("/home/user/project/.worktrees/feature-auth-login"),
        );
    }

    #[test]
    fn worktree_path_no_slashes_passes_through() {
        let repo = Path::new("/repo");
        let result = WorktreeManager::worktree_path(repo, "hotfix");
        assert_eq!(result, PathBuf::from("/repo/.worktrees/hotfix"));
    }

    // -----------------------------------------------------------------------
    // create — command arg verification
    // -----------------------------------------------------------------------

    #[test]
    fn create_builds_correct_command_args() {
        // We cannot easily test the actual git command without a repo, but
        // we can verify the worktree_path helper produces the expected path
        // that create() would use.
        let repo = Path::new("/project");
        let branch = "feature/new-ui";
        let expected_path = PathBuf::from("/project/.worktrees/feature-new-ui");
        assert_eq!(WorktreeManager::worktree_path(repo, branch), expected_path);
    }

    // -----------------------------------------------------------------------
    // Integration tests — real temp git repo
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_create_list_finish_worktree() {
        // Set up a temporary git repo.
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let repo = tmp.path();

        // git init
        let init = Command::new("git")
            .args(["init"])
            .current_dir(repo)
            .output()
            .await;

        let Ok(init_out) = init else {
            eprintln!("git not available — skipping integration test");
            return;
        };
        if !init_out.status.success() {
            eprintln!("git init failed — skipping");
            return;
        }

        // Configure git user for the temp repo (needed for commit).
        let _ = Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(repo)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo)
            .output()
            .await;

        // Create an initial commit (worktree add needs at least one commit).
        let readme = repo.join("README.md");
        tokio::fs::write(&readme, "# test\n")
            .await
            .expect("failed to write readme");

        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(repo)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(repo)
            .output()
            .await;

        // Create a worktree.
        let branch = "feature/test-wt";
        let wt_path = WorktreeManager::worktree_path(repo, branch);

        let create_result = WorktreeManager::create(repo, branch, &wt_path).await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        // List worktrees — should contain the main and the new one.
        let list_result = WorktreeManager::list(repo).await;
        assert!(list_result.is_ok(), "list failed: {list_result:?}");
        let worktrees = list_result.expect("list should succeed");
        assert!(
            worktrees.len() >= 2,
            "expected at least 2 worktrees, got {}: {worktrees:?}",
            worktrees.len(),
        );

        let found = worktrees.iter().any(|w| w.branch == branch);
        assert!(
            found,
            "expected branch '{branch}' in worktree list: {worktrees:?}",
        );

        // Finish the worktree (with merge so branch -d succeeds).
        let finish_result = WorktreeManager::finish(repo, branch, &wt_path, true).await;
        assert!(finish_result.is_ok(), "finish failed: {finish_result:?}");

        // After removal, listing should no longer contain the branch.
        let list_after = WorktreeManager::list(repo)
            .await
            .expect("list should succeed");
        let still_found = list_after.iter().any(|w| w.branch == branch);
        assert!(
            !still_found,
            "branch '{branch}' should be removed: {list_after:?}",
        );

        // The local branch should also be deleted.
        assert!(
            !branch_exists(repo, branch).await,
            "branch '{branch}' should be deleted after finish with merge",
        );
    }

    #[tokio::test]
    async fn integration_finish_unmerged_branch_still_succeeds() {
        // Set up a temporary git repo.
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let repo = tmp.path();

        let init = Command::new("git")
            .args(["init"])
            .current_dir(repo)
            .output()
            .await;

        let Ok(init_out) = init else {
            eprintln!("git not available — skipping integration test");
            return;
        };
        if !init_out.status.success() {
            eprintln!("git init failed — skipping");
            return;
        }

        let _ = Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(repo)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo)
            .output()
            .await;

        let readme = repo.join("README.md");
        tokio::fs::write(&readme, "# test\n")
            .await
            .expect("failed to write readme");

        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(repo)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(repo)
            .output()
            .await;

        // Create a worktree and add an unmerged commit on it.
        let branch = "feature/unmerged";
        let wt_path = WorktreeManager::worktree_path(repo, branch);

        WorktreeManager::create(repo, branch, &wt_path)
            .await
            .expect("create should succeed");

        // Add a commit on the worktree branch so it's unmerged.
        let wt_file = wt_path.join("new-file.txt");
        tokio::fs::write(&wt_file, "unmerged content\n")
            .await
            .expect("failed to write file in worktree");

        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&wt_path)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["commit", "-m", "unmerged work"])
            .current_dir(&wt_path)
            .output()
            .await;

        // Finish without merge — branch -d will fail because unmerged.
        let finish_result = WorktreeManager::finish(repo, branch, &wt_path, false).await;
        assert!(
            finish_result.is_ok(),
            "finish should succeed even when branch is unmerged: {finish_result:?}",
        );

        // The branch should still exist because -d won't delete unmerged.
        assert!(
            branch_exists(repo, branch).await,
            "unmerged branch '{branch}' should be preserved after finish",
        );
    }

    /// Check if a local branch exists in a repository.
    async fn branch_exists(repo: &Path, branch: &str) -> bool {
        let output = Command::new("git")
            .args(["branch", "--list", branch])
            .current_dir(repo)
            .output()
            .await
            .expect("git branch --list should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // `git branch --list` outputs the branch name prefixed with
        // spaces or `*` if it's checked out.
        stdout
            .lines()
            .any(|line| line.trim().trim_start_matches("* ") == branch)
    }
}
