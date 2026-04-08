//! MCP server error types.

/// Errors from the MCP server layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum McpError {
    #[error("JSON-RPC parse error: {message}")]
    ParseError { message: String },

    #[error("invalid method: {method}")]
    MethodNotFound { method: String },

    #[error("invalid params: {message}")]
    InvalidParams { message: String },

    #[error("policy error: {0}")]
    Policy(#[from] sigil_policy::PolicyError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// JSON-RPC 2.0 error codes.
pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
}
