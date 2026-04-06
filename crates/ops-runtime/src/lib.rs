//! ops-runtime — Session runtime backends and tool adapters.
//!
//! This crate implements `SessionRuntime` (from ops-core) using tmux
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
pub mod error;
pub mod tmux;

pub use adapter::claude_code::ClaudeCodeAdapter;
pub use error::RuntimeError;
pub use tmux::TmuxRuntime;
