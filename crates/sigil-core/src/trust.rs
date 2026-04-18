use serde::{Deserialize, Serialize};

/// Trust zones define where in the system a message or action lives.
///
/// Z0 → Z1 → Z2 → Z3 (increasing privilege).
/// Z2 → Z3 is BLOCKED — agents request through MCP, conductor evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TrustZone {
    /// Untrusted ingress: Slack/Telegram payloads, external content.
    Ingress,
    /// Control plane: CLI + conductor orchestration logic.
    ControlPlane,
    /// Agent runtime: tmux sessions or Apple Containers.
    AgentRuntime,
    /// Privileged host ops: filesystem, network, process operations.
    HostPrivileged,
}

/// Permission tiers are UX presets over the capability model.
///
/// The policy engine evaluates capabilities internally; tiers determine
/// the approval UX (auto-allow, confirm, require grant).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Tier {
    /// Read-only operations. Anyone.
    T0,
    /// Operate: create/start/stop sessions, send messages. Sebastian + Paul.
    T1,
    /// Modify infrastructure: worktrees, reparent, reconfigure. Sebastian only (or with grant).
    T2,
    /// Privileged host operations. Sebastian only, confirmed, logged.
    T3,
    /// Break glass. Local CLI only, fully logged, requires justification.
    T3Plus,
}

/// Fine-grained capabilities. These are the internal model — tiers are UX groupings.
///
/// Each Action variant maps to one capability. The policy engine checks
/// capabilities, not tiers directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Capability {
    // T0
    ReadSessionInfo,
    ReadSystemStatus,

    // T1
    ManageSession,
    SendMessage,
    /// Fetch and consume external content (URLs, remote resources).
    /// Requires a grant; not automatically authorized. The resulting
    /// `ActionResult` must carry a [`crate::content::SanitizeReport`]
    /// when the originating action declares a
    /// [`crate::content::SanitizationRequirement::Required`].
    FetchExternalContent,

    // T2
    ModifyInfrastructure,
    ConfigureConductor,

    // T3 — effect classes
    ReadHostFile,
    WriteHostFile,
    ExecuteHostCommand,
    ModifyGitState,
    ExternalNetworkWrite,
    ServiceControl,

    // T3+
    BreakGlass,
}

impl Capability {
    /// The minimum tier required for this capability.
    #[must_use]
    pub fn minimum_tier(&self) -> Tier {
        match self {
            Self::ReadSessionInfo | Self::ReadSystemStatus => Tier::T0,
            Self::ManageSession | Self::SendMessage | Self::FetchExternalContent => Tier::T1,
            Self::ModifyInfrastructure | Self::ConfigureConductor => Tier::T2,
            Self::ReadHostFile
            | Self::WriteHostFile
            | Self::ExecuteHostCommand
            | Self::ModifyGitState
            | Self::ExternalNetworkWrite
            | Self::ServiceControl => Tier::T3,
            Self::BreakGlass => Tier::T3Plus,
        }
    }
}

/// Execution class determines container config, network policy, and tier ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExecutionClass {
    /// No network. Project filesystem only. T0 ceiling.
    OfflineWorker,
    /// GET to allowlisted domains. T1 ceiling.
    ResearchWorker,
    /// Full allowlisted network (including POST). T1 ceiling.
    Builder,
}

impl ExecutionClass {
    /// The maximum tier an agent in this execution class can request.
    #[must_use]
    pub fn tier_ceiling(&self) -> Tier {
        match self {
            Self::OfflineWorker => Tier::T0,
            Self::ResearchWorker | Self::Builder => Tier::T1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_have_correct_tier_mapping() {
        assert_eq!(Capability::ReadSessionInfo.minimum_tier(), Tier::T0);
        assert_eq!(Capability::ManageSession.minimum_tier(), Tier::T1);
        assert_eq!(Capability::FetchExternalContent.minimum_tier(), Tier::T1);
        assert_eq!(Capability::ModifyInfrastructure.minimum_tier(), Tier::T2);
        assert_eq!(Capability::ReadHostFile.minimum_tier(), Tier::T3);
        assert_eq!(Capability::BreakGlass.minimum_tier(), Tier::T3Plus);
    }

    #[test]
    fn tiers_are_ordered() {
        assert!(Tier::T0 < Tier::T1);
        assert!(Tier::T1 < Tier::T2);
        assert!(Tier::T2 < Tier::T3);
        assert!(Tier::T3 < Tier::T3Plus);
    }

    #[test]
    fn execution_class_ceilings() {
        assert_eq!(ExecutionClass::OfflineWorker.tier_ceiling(), Tier::T0);
        assert_eq!(ExecutionClass::ResearchWorker.tier_ceiling(), Tier::T1);
        assert_eq!(ExecutionClass::Builder.tier_ceiling(), Tier::T1);
    }
}
