//! sigil-runtime — Session runtime backends and tool adapters.
//!
//! This crate implements `SessionRuntime` (from sigil-core) using tmux
//! as the backend, and provides `ToolAdapter` implementations for
//! translating between structured conductor messages and terminal I/O.
//!
//! **Key design rules:**
//! - `SessionRuntime` is tmux-agnostic at the trait level; tmux types
//!   never leak into core/policy/conductor.
//! - Terminal parsing is **observability only** — `parse_output()`
//!   produces `AgentSignal`, never `ActionRequest`.
//! - All tmux interaction goes through `tokio::process::Command`.

pub mod adapter;
pub mod config;
#[cfg(feature = "container")]
pub mod container;
pub mod error;
#[cfg(feature = "container")]
pub(crate) mod mcp_socket;
#[cfg(feature = "container")]
pub mod proxy;
pub mod tmux;
pub mod worktree;

pub use adapter::claude_code::ClaudeCodeAdapter;
pub use config::ToolConfig;
#[cfg(feature = "container")]
pub use container::{ContainerConfig, ContainerRuntime, NetworkMode};
pub use error::RuntimeError;
#[cfg(feature = "container")]
pub use mcp_socket::mcp_socket_path;
#[cfg(feature = "container")]
pub use proxy::{DomainAllowlist, DomainProxy};
pub use tmux::TmuxRuntime;
pub use worktree::{WorktreeInfo, WorktreeManager};
