//! sigil-mcp — Host-side MCP server for policy-mediated agent actions.
//!
//! This crate implements the Model Context Protocol (MCP) server that
//! agents use to request privileged actions. Every request goes through
//! the sigil policy engine before any effect occurs.
//!
//! # Architecture
//!
//! ```text
//! Agent in container/session
//!   → MCP tool call (JSON-RPC over stdin/stdout)
//!   → sigil-mcp server
//!   → ActionRequest created
//!   → sigil-policy evaluates
//!   → result returned to agent (allowed / denied / needs-approval)
//! ```
//!
//! The MCP server is a **policy-mediated proxy**, not a host shell.
//! It cannot execute host commands directly — it only evaluates
//! whether actions should be permitted.
//!
//! # Transport
//!
//! Standard MCP transport: JSON-RPC 2.0 over stdin/stdout, one message
//! per line.

pub mod error;
pub mod server;
pub mod tools;
pub mod transport;

pub use error::McpError;
pub use server::{McpServer, handle_stream, run_stdio};
pub use tools::{McpTool, ToolResult, ToolStatus};
pub use transport::{JsonRpcRequest, JsonRpcResponse};
