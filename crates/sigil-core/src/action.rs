use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::content::{SanitizationRequirement, SanitizeReport};
use crate::id::{GroupId, RequestId, SessionId};
use crate::origin::ActionOrigin;
use crate::session::{ConductorConfig, IdentitySpec, ToolKind};
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
        group: Option<GroupId>,
        tool: ToolKind,
        identity: Option<IdentitySpec>,
    },
    LaunchSession {
        path: PathBuf,
        title: String,
        tool: ToolKind,
        group: Option<GroupId>,
        message: Option<String>,
        identity: Option<IdentitySpec>,
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
        group: GroupId,
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

    /// Whether this action's [`ActionResult`] must carry a
    /// [`SanitizeReport`], and if so, over what content type.
    ///
    /// No current variant fetches external content, so the default is
    /// [`SanitizationRequirement::None`]. A future `FetchUrl` (or
    /// equivalent) variant will override this to declare
    /// [`SanitizationRequirement::Required`] — the policy evaluator then
    /// enforces that the post-dispatch result carries a matching report.
    #[must_use]
    pub fn sanitization_requirement(&self) -> SanitizationRequirement {
        SanitizationRequirement::None
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

/// Post-dispatch result of an [`ActionRequest`].
///
/// This is a thin envelope: the structural payload (session records,
/// text, list views, …) lives in `sigil-conductor`'s `DispatchResult`
/// to keep the core crate free of runtime dependencies. What core owns
/// is the **policy-relevant** metadata produced alongside the payload —
/// at PR6, that is the optional [`SanitizeReport`] attached to results
/// of actions that fetched external content.
///
/// The evaluator's post-dispatch check consults `sanitize_report` to
/// enforce [`SanitizationRequirement::Required`] on the originating
/// action. Audit writers serialize the full struct so the report
/// survives round-trip through the HMAC-chained audit log.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ActionResult {
    /// The sanitizer report, when the dispatched action produced
    /// external content. `None` when no sanitization took place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitize_report: Option<SanitizeReport>,
}

impl ActionResult {
    /// An empty result — no sanitize report attached.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a [`SanitizeReport`] to the result. Chainable builder.
    #[must_use]
    pub fn with_sanitize_report(mut self, report: SanitizeReport) -> Self {
        self.sanitize_report = Some(report);
        self
    }

    /// Whether this result carries a [`SanitizeReport`].
    #[must_use]
    pub fn has_sanitize_report(&self) -> bool {
        self.sanitize_report.is_some()
    }
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]

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

    #[test]
    fn all_existing_actions_have_no_sanitization_requirement() {
        // No Action variant fetches external content today, so every
        // variant must default to SanitizationRequirement::None. This
        // test guards the invariant so a future variant that declares
        // a requirement can't be added without updating both the enum
        // and this test (forcing the policy wiring to be considered).
        let actions = [
            Action::ListSessions,
            Action::ListGroups,
            Action::GetSystemStatus,
            Action::StartSession {
                session_id: SessionId::new(),
            },
            Action::ExternalNetworkWrite {
                domain: "example.com".into(),
                method: HttpMethod::Get,
                path: "/".into(),
            },
        ];
        for action in &actions {
            assert_eq!(
                action.sanitization_requirement(),
                crate::content::SanitizationRequirement::None,
                "{action:?} must default to None"
            );
        }
    }

    #[test]
    fn action_result_new_has_no_report() {
        let result = ActionResult::new();
        assert!(!result.has_sanitize_report());
        assert!(result.sanitize_report.is_none());
    }

    #[test]
    fn action_result_round_trips_without_report() {
        let result = ActionResult::new();
        let json = serde_json::to_string(&result).expect("serialize");
        // Empty report must not leak a `null` field — it should round-trip
        // cleanly through older deserializers.
        assert!(!json.contains("sanitize_report"), "got: {json}");
        let back: ActionResult = serde_json::from_str(&json).expect("deserialize");
        assert!(!back.has_sanitize_report());
    }

    #[test]
    fn action_result_round_trips_with_report() {
        use crate::content::{
            ContentSource, ContentType, Fingerprint, REPORT_SCHEMA_VERSION, SanitizeReport,
        };
        use crate::normalize::NormalizeResult;

        let key = b"test-audit-key";
        let report = SanitizeReport {
            schema_version: REPORT_SCHEMA_VERSION,
            rule_set_version: 1,
            scoring_version: 1,
            source: ContentSource::from_url("https://example.com/doc").expect("url"),
            content_type: ContentType::Html,
            bytes_in: 10,
            bytes_out: 8,
            stripped_elements: vec![],
            text_normalize: NormalizeResult::default(),
            findings: vec![],
            risk_score: 3,
            repetition_ratio: 0.0,
            size_rejected: false,
            encoding_rejected: false,
            nonce: "deadbeef".into(),
            duration_ms: 1,
            raw_fingerprint: Fingerprint::compute(key, b"raw").expect("fp"),
            sanitized_fingerprint: Fingerprint::compute(key, b"clean").expect("fp"),
        };

        let result = ActionResult::new().with_sanitize_report(report.clone());
        assert!(result.has_sanitize_report());

        let json = serde_json::to_string(&result).expect("serialize");
        let back: ActionResult = serde_json::from_str(&json).expect("deserialize");
        let back_report = back
            .sanitize_report
            .expect("report present after round-trip");
        assert_eq!(back_report.nonce, report.nonce);
        assert_eq!(back_report.content_type, report.content_type);
        assert_eq!(back_report.raw_fingerprint, report.raw_fingerprint);
    }
}

#[cfg(test)]
mod proptest_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::path::PathBuf;

    use proptest::prelude::*;

    use super::*;
    use crate::id::{GroupId, SessionId};
    use crate::session::{ConductorConfig, ToolKind};
    use crate::trust::Tier;

    fn arb_session_id() -> impl Strategy<Value = SessionId> {
        Just(()).prop_map(|()| SessionId::new())
    }

    fn arb_path() -> impl Strategy<Value = PathBuf> {
        "[a-z]{1,8}(/[a-z]{1,8}){0,3}".prop_map(|s| PathBuf::from(format!("/tmp/{s}")))
    }

    fn arb_name() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,20}"
    }

    fn arb_tool_kind() -> impl Strategy<Value = ToolKind> {
        prop_oneof![Just(ToolKind::ClaudeCode), Just(ToolKind::Codex)]
    }

    fn arb_http_method() -> impl Strategy<Value = HttpMethod> {
        prop_oneof![
            Just(HttpMethod::Get),
            Just(HttpMethod::Post),
            Just(HttpMethod::Put),
            Just(HttpMethod::Patch),
            Just(HttpMethod::Delete),
        ]
    }

    fn arb_command_template() -> impl Strategy<Value = CommandTemplate> {
        arb_path().prop_flat_map(|path| {
            prop_oneof![
                Just(CommandTemplate::CargoTest { path: path.clone() }),
                Just(CommandTemplate::CargoClippy { path: path.clone() }),
                Just(CommandTemplate::CargoFmt { path: path.clone() }),
                Just(CommandTemplate::NpmTest { path: path.clone() }),
                Just(CommandTemplate::NpmInstall { path: path.clone() }),
                Just(CommandTemplate::NpmBuild { path: path.clone() }),
                Just(CommandTemplate::PythonTest { path: path.clone() }),
                Just(CommandTemplate::GitPull { repo: path }),
            ]
        })
    }

    fn arb_git_operation() -> impl Strategy<Value = GitOperation> {
        prop_oneof![
            (arb_name(), arb_name())
                .prop_map(|(remote, branch)| GitOperation::Push { remote, branch }),
            arb_name().prop_map(|name| GitOperation::CreateBranch { name }),
            arb_name().prop_map(|name| GitOperation::DeleteBranch { name }),
            arb_name().prop_map(|branch| GitOperation::Merge { branch }),
            arb_name().prop_map(|name| GitOperation::Tag { name }),
        ]
    }

    fn arb_service_name() -> impl Strategy<Value = ServiceName> {
        prop_oneof![
            Just(ServiceName::Bridge),
            arb_name().prop_map(|name| ServiceName::Conductor { name }),
        ]
    }

    fn arb_conductor_config() -> impl Strategy<Value = ConductorConfig> {
        (
            arb_name(),
            any::<bool>(),
            1u64..3600u64,
            proptest::collection::vec(arb_name(), 0..3),
        )
            .prop_map(
                |(name, auto_response_enabled, heartbeat_interval_secs, escalation_channels)| {
                    ConductorConfig {
                        name,
                        auto_response_enabled,
                        heartbeat_interval_secs,
                        escalation_channels,
                    }
                },
            )
    }

    /// Strategy that generates every `Action` variant with valid inner data.
    ///
    /// Split into groups of ≤10 for `prop_oneof!` (which uses `TupleUnion`
    /// internally and supports at most 10 branches per call).
    fn arb_action() -> impl Strategy<Value = Action> {
        // Group A: T0 (5) + first 5 of T1 = 10
        let read_operate = prop_oneof![
            Just(Action::ListSessions),
            arb_session_id().prop_map(|session_id| Action::GetSessionStatus { session_id }),
            arb_session_id().prop_map(|session_id| Action::ReadSessionOutput { session_id }),
            Just(Action::ListGroups),
            Just(Action::GetSystemStatus),
            (
                arb_path(),
                arb_name(),
                proptest::option::of(arb_name()),
                arb_tool_kind(),
            )
                .prop_map(|(path, title, group, tool)| Action::CreateSession {
                    path,
                    title,
                    group: group.map(GroupId::new),
                    tool,
                    identity: None,
                }),
            (
                arb_path(),
                arb_name(),
                arb_tool_kind(),
                proptest::option::of(arb_name()),
                proptest::option::of(arb_name()),
            )
                .prop_map(|(path, title, tool, group, message)| {
                    Action::LaunchSession {
                        path,
                        title,
                        tool,
                        group: group.map(GroupId::new),
                        message,
                        identity: None,
                    }
                }),
            arb_session_id().prop_map(|session_id| Action::StartSession { session_id }),
            arb_session_id().prop_map(|session_id| Action::StopSession { session_id }),
            arb_session_id().prop_map(|session_id| Action::RestartSession { session_id }),
        ];

        // Group B: remaining T1 (2) + T2 (6) = 8
        let operate_infra = prop_oneof![
            (arb_session_id(), arb_name()).prop_map(|(session_id, message)| {
                Action::SendMessage {
                    session_id,
                    message,
                }
            }),
            arb_session_id().prop_map(|session_id| Action::RemoveSession { session_id }),
            (arb_session_id(), arb_name())
                .prop_map(|(session_id, branch)| { Action::CreateWorktree { session_id, branch } }),
            (arb_session_id(), any::<bool>())
                .prop_map(|(session_id, merge)| Action::FinishWorktree { session_id, merge }),
            (arb_session_id(), arb_session_id()).prop_map(|(session_id, parent_id)| {
                Action::SetSessionParent {
                    session_id,
                    parent_id,
                }
            }),
            (arb_session_id(), arb_name()).prop_map(|(session_id, new_title)| {
                Action::RenameSession {
                    session_id,
                    new_title,
                }
            }),
            (arb_session_id(), arb_name()).prop_map(|(session_id, group)| {
                Action::MoveSessionToGroup {
                    session_id,
                    group: GroupId::new(group),
                }
            }),
            (arb_name(), arb_conductor_config())
                .prop_map(|(name, config)| Action::ConfigureConductor { name, config }),
        ];

        // Group C: T3 (6) + T3+ (1) = 7
        let privileged = prop_oneof![
            arb_path().prop_map(|path| Action::ReadHostFile { path }),
            (arb_path(), proptest::collection::vec(any::<u8>(), 0..64))
                .prop_map(|(path, content)| Action::WriteHostFile { path, content }),
            (arb_path(), arb_git_operation())
                .prop_map(|(repo, operation)| Action::ModifyGitState { repo, operation }),
            arb_command_template().prop_map(|template| Action::ExecuteHostCommand { template }),
            arb_service_name().prop_map(|service| Action::RestartService { service }),
            (arb_name(), arb_http_method(), arb_name()).prop_map(|(domain, method, path)| {
                Action::ExternalNetworkWrite {
                    domain,
                    method,
                    path,
                }
            },),
            (
                proptest::collection::vec(arb_name(), 1..5),
                arb_path(),
                arb_name(),
            )
                .prop_map(|(command, cwd, justification)| Action::BreakGlass {
                    command,
                    cwd,
                    justification,
                }),
        ];

        prop_oneof![read_operate, operate_infra, privileged]
    }

    proptest! {
        /// Every generated Action variant maps to a valid Capability
        /// whose minimum tier is within the defined range.
        #[test]
        fn all_actions_have_valid_tier_assignment(action in arb_action()) {
            let cap = action.required_capability();
            let tier = cap.minimum_tier();
            prop_assert!(tier <= Tier::T3Plus, "tier {tier:?} exceeds T3Plus");
        }

        /// The capability mapping is consistent: calling required_capability
        /// twice on the same action always returns the same capability.
        #[test]
        fn required_capability_is_deterministic(action in arb_action()) {
            let c1 = action.required_capability();
            let c2 = action.required_capability();
            prop_assert_eq!(c1, c2);
        }
    }
}
