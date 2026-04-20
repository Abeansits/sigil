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
    /// Create a git worktree for a session on a freshly created branch.
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
        Self::create_with_options(repo, branch, worktree_path, true).await
    }

    /// Create a git worktree, optionally creating the branch.
    ///
    /// When `create_branch` is `true`, runs
    /// `git worktree add -b {branch} {worktree_path}` and fails if the
    /// branch already exists. When `false`, runs
    /// `git worktree add {worktree_path} {branch}` to attach an
    /// existing branch and fails if the branch does not exist.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the git command fails.
    pub async fn create_with_options(
        repo: &Path,
        branch: &str,
        worktree_path: &Path,
        create_branch: bool,
    ) -> Result<(), RuntimeError> {
        let wt_str = worktree_path
            .to_str()
            .ok_or_else(|| RuntimeError::GitCommand {
                command: "worktree add".to_owned(),
                stderr: "worktree path is not valid UTF-8".to_owned(),
            })?;

        let (args, command_desc): (Vec<&str>, String) = if create_branch {
            (
                vec!["worktree", "add", "-b", branch, wt_str],
                format!("git worktree add -b {branch} {wt_str}"),
            )
        } else {
            (
                vec!["worktree", "add", wt_str, branch],
                format!("git worktree add {wt_str} {branch}"),
            )
        };

        let output = Command::new("git")
            .args(&args)
            .current_dir(repo)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(RuntimeError::GitCommand {
                command: command_desc,
                stderr,
            });
        }

        debug!(
            repo = %repo.display(),
            branch,
            worktree = %worktree_path.display(),
            create_branch,
            "created worktree",
        );
        Ok(())
    }

    /// Check whether a local branch exists in a repository.
    ///
    /// Runs `git rev-parse --verify --quiet refs/heads/{branch}` inside
    /// `repo`. Treats a non-zero exit as "branch does not exist" and any
    /// I/O failure as a propagated error.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the git command could not be spawned.
    pub async fn branch_exists(repo: &Path, branch: &str) -> Result<bool, RuntimeError> {
        let ref_spec = format!("refs/heads/{branch}");
        let output = Command::new("git")
            .args(["rev-parse", "--verify", "--quiet", &ref_spec])
            .current_dir(repo)
            .output()
            .await?;

        Ok(output.status.success())
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

    /// Best-effort rollback for a worktree that was created as part of
    /// a compound flow (e.g. `session launch --worktree`) but could not
    /// be fully wired up.
    ///
    /// Existence-aware and idempotent: only runs
    /// `git worktree remove --force` when the directory is actually
    /// present, and only runs `git branch -D` when `delete_branch`
    /// is true AND the branch currently exists. That matters because
    /// `git worktree add -b <branch> <path>` creates the branch before
    /// binding the path, so a failed `add` can leave behind the branch
    /// without ever materialising the worktree directory. Callers
    /// therefore pass `delete_branch = create_branch` (the original
    /// `-b` flag), not some observed-success flag.
    ///
    /// `--force` (worktree) and `-D` (branch) are used instead of the
    /// safer `-d` variant because any content on disk came from *this*
    /// half-failed launch — there is nothing to preserve. Attached
    /// branches (`delete_branch = false`) are always left alone so a
    /// partially-failed launch never clobbers pre-existing branch
    /// state.
    ///
    /// All failures are logged at `warn` but never propagated, so
    /// callers can layer this rollback behind other cleanup without
    /// juggling nested errors.
    pub async fn rollback_new_worktree(
        repo: &Path,
        branch: &str,
        worktree_path: &Path,
        delete_branch: bool,
    ) {
        if worktree_path.exists() {
            if let Some(wt_str) = worktree_path.to_str() {
                let res = Command::new("git")
                    .args(["worktree", "remove", "--force", wt_str])
                    .current_dir(repo)
                    .output()
                    .await;

                match res {
                    Ok(out) if out.status.success() => {
                        debug!(
                            repo = %repo.display(),
                            worktree = %worktree_path.display(),
                            "rolled back worktree",
                        );
                    }
                    Ok(out) => {
                        warn!(
                            repo = %repo.display(),
                            worktree = %worktree_path.display(),
                            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                            "git worktree remove --force failed during rollback",
                        );
                    }
                    Err(e) => {
                        warn!(
                            repo = %repo.display(),
                            worktree = %worktree_path.display(),
                            error = %e,
                            "failed to spawn git for worktree rollback",
                        );
                    }
                }
            } else {
                warn!(
                    repo = %repo.display(),
                    "worktree path is not valid UTF-8; cannot roll back",
                );
            }
        }

        if delete_branch {
            // Only delete the branch if it actually exists — git worktree
            // add can leave behind a fresh branch even when the add fails,
            // but might also never reach that point. branch_exists errors
            // propagate as "no cleanup" rather than crashing the rollback.
            let exists = Self::branch_exists(repo, branch).await.unwrap_or(false);
            if exists {
                let res = Command::new("git")
                    .args(["branch", "-D", branch])
                    .current_dir(repo)
                    .output()
                    .await;

                match res {
                    Ok(out) if out.status.success() => {
                        debug!(repo = %repo.display(), branch, "rolled back branch");
                    }
                    Ok(out) => {
                        warn!(
                            repo = %repo.display(),
                            branch,
                            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                            "git branch -D failed during rollback",
                        );
                    }
                    Err(e) => {
                        warn!(
                            repo = %repo.display(),
                            branch,
                            error = %e,
                            "failed to spawn git for branch rollback",
                        );
                    }
                }
            }
        }
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

    #[tokio::test]
    async fn integration_branch_exists_and_attach_and_rollback() {
        let tmp = tempfile::tempdir().expect("tempdir");
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

        for args in [
            &["config", "user.email", "test@test.com"][..],
            &["config", "user.name", "Test"][..],
        ] {
            let _ = Command::new("git")
                .args(args)
                .current_dir(repo)
                .output()
                .await;
        }

        tokio::fs::write(repo.join("README.md"), "# test\n")
            .await
            .expect("readme");

        for args in [&["add", "."][..], &["commit", "-m", "initial"][..]] {
            let _ = Command::new("git")
                .args(args)
                .current_dir(repo)
                .output()
                .await;
        }

        // ---- branch_exists ----
        assert!(
            !WorktreeManager::branch_exists(repo, "not-a-branch")
                .await
                .expect("branch_exists runs"),
            "missing branch reports false",
        );

        // Create a detached branch (without checking it out) for the attach case.
        let attach_branch = "feature/attach-me";
        let _ = Command::new("git")
            .args(["branch", attach_branch])
            .current_dir(repo)
            .output()
            .await;

        assert!(
            WorktreeManager::branch_exists(repo, attach_branch)
                .await
                .expect("branch_exists runs"),
            "existing branch reports true",
        );

        // ---- create_with_options attach path (create_branch=false) ----
        let wt_path = WorktreeManager::worktree_path(repo, attach_branch);
        WorktreeManager::create_with_options(repo, attach_branch, &wt_path, false)
            .await
            .expect("attach should succeed for existing branch");
        assert!(wt_path.exists());

        // Rolling back an attached worktree must NOT delete the branch.
        WorktreeManager::rollback_new_worktree(repo, attach_branch, &wt_path, false).await;
        assert!(
            !wt_path.exists(),
            "worktree dir should be gone after rollback"
        );
        assert!(
            branch_exists(repo, attach_branch).await,
            "attached branch must survive rollback",
        );

        // ---- create_with_options create-branch path then rollback (delete_branch=true) ----
        let fresh_branch = "feature/fresh-for-rollback";
        let fresh_wt = WorktreeManager::worktree_path(repo, fresh_branch);
        WorktreeManager::create_with_options(repo, fresh_branch, &fresh_wt, true)
            .await
            .expect("create with -b should succeed");

        assert!(fresh_wt.exists());
        assert!(branch_exists(repo, fresh_branch).await);

        WorktreeManager::rollback_new_worktree(repo, fresh_branch, &fresh_wt, true).await;
        assert!(!fresh_wt.exists());
        assert!(
            !branch_exists(repo, fresh_branch).await,
            "freshly-created branch should be deleted on rollback",
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
        // `git branch --list` prefixes lines with ` ` (inactive),
        // `* ` (checked out in this worktree), or `+ ` (checked out
        // in another worktree).
        stdout.lines().any(|line| {
            let trimmed = line
                .trim()
                .trim_start_matches("* ")
                .trim_start_matches("+ ");
            trimmed == branch
        })
    }
}
