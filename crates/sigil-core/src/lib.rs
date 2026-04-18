//! sigil-core — Domain models, action enum, and trait ports.
//!
//! This is the foundation crate. It defines the types and traits that
//! every other crate in the workspace depends on. No internal dependencies.
//!
//! **Key design rules:**
//! - The `Action` enum is the sole authority-bearing protocol.
//! - No `Shell(String)` or raw command variants.
//! - Terminal parsing is observability only — never authority.
//! - Every function that does anything takes a policy context.

pub mod action;
pub mod config;
pub mod content;
pub mod episode;
pub mod error;
pub mod id;
pub mod normalize;
pub mod origin;
pub mod principal;
pub mod protocol;
pub mod session;
pub mod traits;
pub mod trust;

// Re-export the most commonly used types at crate root for ergonomics.
pub use action::{
    Action, ActionRequest, ActionResult, CommandTemplate, GitOperation, PolicyDecision,
};
pub use config::{
    BridgeConfigSection, BridgePlatformConfig, BridgeUserEntry, MemoryConfig, MemoryConfigSection,
    parse_tier,
};
pub use content::{
    ByteRange, ContentError, ContentSource, ContentType, Finding, Fingerprint,
    REPORT_SCHEMA_VERSION, SanitizationRequirement, SanitizeReport, SanitizedContent, Severity,
    UrlSource,
};
pub use episode::{EpisodeEvent, EpisodeId, EpisodeKind};
pub use error::CoreError;
pub use id::{GroupId, RequestId, SessionId};
pub use normalize::NormalizeResult;
pub use origin::ActionOrigin;
pub use principal::{PlatformIdentity, Principal};
pub use protocol::{AgentSignal, BridgeMessage, ConductorMessage, ReplyContext};
pub use session::{
    IdentitySpec, LifecycleEvent, SessionConfig, SessionHandle, SessionRecord, SessionState,
    ToolKind,
};
pub use traits::{
    ActionRouter, AuditEvent, AuditWriter, LifecycleHooks, MessageSink, MessageSource,
    PolicyEngine, SessionRuntime, ToolAdapter,
};
pub use trust::{Capability, ExecutionClass, Tier, TrustZone};
