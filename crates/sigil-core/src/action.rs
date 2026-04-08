use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::id::{RequestId, SessionId};
use crate::origin::ActionOrigin;
use crate::session::{ConductorConfig, ToolKind};
use crate::trust::Capability;

/// A request to perform an action. The sole authority-bearing protocol.
///
/// Every operation in the system is an `ActionRequest`. No string commands
/// cross module boundaries. The policy engine evaluates this against the
/// principal's permissions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionRequest {
    pub id: RequestId,
    pub action: Action,
    pub origin: ActionOrigin,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
}

impl ActionRequest {
    #[must_use]
    pub fn new(action: Action, origin: ActionOrigin) -> Self {
        Self {
            id: RequestId::new(),
            action,
            origin,
            timestamp: OffsetDateTime::now_utc(),
        }
    }
}

/// Every operation in the system. No `Shell(String)` variant.
///
/// Host actions are enumerated capabilities, not arbitrary shell commands.
/// `ExecuteHostCommand` uses `CommandTemplate` (named, validated commands).
/// Raw commands are only available via `BreakGlass` (local-only, logged,
/// requires justification).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Action {
    // --- T0: Read (anyone) ---
    ListSessions,
    GetSessionStatus {
        session_id: SessionId,
    },
    ReadSessionOutput {
        session_id: SessionId,
    },
    ListGroups,
    GetSystemStatus,

    // --- T1: Operate (Sebastian, Paul) ---
    CreateSession {
        path: PathBuf,
        title: String,
        group: Option<String>,
        tool: ToolKind,
    },
    LaunchSession {
        path: PathBuf,
        title: String,
        message: Option<String>,
    },
    StartSession {
        session_id: SessionId,
    },
    StopSession {
        session_id: SessionId,
    },
    RestartSession {
        session_id: SessionId,
    },
    SendMessage {
        session_id: SessionId,
        message: String,
    },
    RemoveSession {
        session_id: SessionId,
    },

    // --- T2: Modify Infrastructure (Sebastian only, or with grant) ---
    CreateWorktree {
        session_id: SessionId,
        branch: String,
    },
    FinishWorktree {
        session_id: SessionId,
        merge: bool,
    },
    SetSessionParent {
        session_id: SessionId,
        parent_id: SessionId,
    },
    RenameSession {
        session_id: SessionId,
        new_title: String,
    },
    MoveSessionToGroup {
        session_id: SessionId,
        group: String,
    },
    ConfigureConductor {
        name: String,
        config: ConductorConfig,
    },

    // --- T3: Privileged — Host Observation ---
    ReadHostFile {
        path: PathBuf,
    },

    // --- T3: Privileged — Host Mutation ---
    WriteHostFile {
        path: PathBuf,
        content: Vec<u8>,
    },
    ModifyGitState {
        repo: PathBuf,
        operation: GitOperation,
    },

    // --- T3: Privileged — Host Execution (named templates, not raw argv) ---
    ExecuteHostCommand {
        template: CommandTemplate,
    },
    RestartService {
        service: ServiceName,
    },

    // --- T3: Privileged — External Network Write ---
    ExternalNetworkWrite {
        domain: String,
        method: HttpMethod,
        path: String,
    },

    // --- T3+: Break Glass (local-only, fully logged, requires justification) ---
    BreakGlass {
        command: Vec<String>,
        cwd: PathBuf,
        justification: String,
    },
}

impl Action {
    /// The resource scope for this action, if any.
    ///
    /// Used by the policy evaluator to match against approval grant
    /// resource scopes. Returns the file path, repo path, or domain
    /// associated with the action.
    #[must_use]
    #[allow(clippy::wildcard_enum_match_arm)]
    pub fn resource_scope(&self) -> Option<String> {
        match self {
            Self::ReadHostFile { path } | Self::WriteHostFile { path, .. } => {
                Some(path.to_string_lossy().into_owned())
            }
            Self::ModifyGitState { repo, .. } => Some(repo.to_string_lossy().into_owned()),
            Self::ExternalNetworkWrite { domain, .. } => Some(domain.clone()),
            Self::BreakGlass { cwd, .. } => Some(cwd.to_string_lossy().into_owned()),
            // Actions without a resource scope (T0-T2 operations, named
            // templates, services). The exhaustive list is intentionally
            // covered by a wildcard + non_exhaustive to handle future variants.
            _ => None,
        }
    }

    /// The capability required for this action.
    #[must_use]
    pub fn required_capability(&self) -> Capability {
        match self {
            Self::ListSessions
            | Self::GetSessionStatus { .. }
            | Self::ReadSessionOutput { .. }
            | Self::ListGroups
            | Self::GetSystemStatus => Capability::ReadSessionInfo,

            Self::CreateSession { .. }
            | Self::LaunchSession { .. }
            | Self::StartSession { .. }
            | Self::StopSession { .. }
            | Self::RestartSession { .. }
            | Self::RemoveSession { .. } => Capability::ManageSession,

            Self::SendMessage { .. } => Capability::SendMessage,

            Self::CreateWorktree { .. }
            | Self::FinishWorktree { .. }
            | Self::SetSessionParent { .. }
            | Self::RenameSession { .. }
            | Self::MoveSessionToGroup { .. } => Capability::ModifyInfrastructure,

            Self::ConfigureConductor { .. } => Capability::ConfigureConductor,

            Self::ReadHostFile { .. } => Capability::ReadHostFile,
            Self::WriteHostFile { .. } => Capability::WriteHostFile,
            Self::ExecuteHostCommand { .. } => Capability::ExecuteHostCommand,
            Self::ModifyGitState { .. } => Capability::ModifyGitState,
            Self::ExternalNetworkWrite { .. } => Capability::ExternalNetworkWrite,
            Self::RestartService { .. } => Capability::ServiceControl,
            Self::BreakGlass { .. } => Capability::BreakGlass,
        }
    }
}

/// Named, validated host commands. Not raw argv.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CommandTemplate {
    CargoTest { path: PathBuf },
    CargoClippy { path: PathBuf },
    CargoFmt { path: PathBuf },
    NpmTest { path: PathBuf },
    NpmInstall { path: PathBuf },
    NpmBuild { path: PathBuf },
    PythonTest { path: PathBuf },
    GitPull { repo: PathBuf },
}

/// Git state mutations. Each variant is a specific, auditable operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GitOperation {
    Push { remote: String, branch: String },
    CreateBranch { name: String },
    DeleteBranch { name: String },
    Merge { branch: String },
    Tag { name: String },
}

/// Named services that can be restarted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ServiceName {
    Bridge,
    Conductor { name: String },
}

/// HTTP methods for tracking external network writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// The result of evaluating an action request through the policy engine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Action is allowed. Proceed.
    Allow,
    /// Action is denied. Includes reason.
    Deny { reason: String },
    /// Action requires human approval. Pending grant.
    NeedsApproval { description: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::Tier;

    #[test]
    fn read_actions_require_t0_capability() {
        let actions = [
            Action::ListSessions,
            Action::GetSystemStatus,
            Action::ListGroups,
        ];
        for action in &actions {
            let cap = action.required_capability();
            assert_eq!(cap.minimum_tier(), Tier::T0, "failed for {action:?}");
        }
    }

    #[test]
    fn session_management_requires_t1() {
        let action = Action::StartSession {
            session_id: SessionId::new(),
        };
        assert_eq!(action.required_capability().minimum_tier(), Tier::T1,);
    }

    #[test]
    fn host_file_read_requires_t3() {
        let action = Action::ReadHostFile {
            path: PathBuf::from("/etc/hosts"),
        };
        assert_eq!(action.required_capability().minimum_tier(), Tier::T3,);
    }

    #[test]
    fn break_glass_requires_t3plus() {
        let action = Action::BreakGlass {
            command: vec!["ls".into()],
            cwd: PathBuf::from("/tmp"),
            justification: "testing".into(),
        };
        assert_eq!(action.required_capability().minimum_tier(), Tier::T3Plus,);
    }

    #[test]
    fn action_request_has_unique_id() {
        let origin = ActionOrigin::LocalCli;
        let r1 = ActionRequest::new(Action::ListSessions, origin.clone());
        let r2 = ActionRequest::new(Action::ListSessions, origin);
        assert_ne!(r1.id, r2.id);
    }
}
