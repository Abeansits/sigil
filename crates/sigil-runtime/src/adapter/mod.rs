pub mod claude_code;

use sigil_core::session::ToolKind;
use sigil_core::traits::ToolAdapter;

use self::claude_code::ClaudeCodeAdapter;

/// Return the appropriate adapter for the given tool kind.
///
/// All tool kinds currently use the `ClaudeCodeAdapter`. As dedicated
/// adapters are implemented (e.g. Codex, `OpenCode`), this function will
/// dispatch to them. `tool_has_readiness_markers` in `tmux.rs` gates
/// the readiness poll so adapter mismatches don't stall on unfamiliar
/// prompt shapes.
#[allow(clippy::match_same_arms, clippy::wildcard_enum_match_arm)]
pub fn adapter_for(tool: ToolKind) -> Box<dyn ToolAdapter> {
    match tool {
        ToolKind::ClaudeCode => Box::new(ClaudeCodeAdapter::new()),
        ToolKind::Codex => Box::new(ClaudeCodeAdapter::new()),
        ToolKind::OpenCode => Box::new(ClaudeCodeAdapter::new()),
        _ => Box::new(ClaudeCodeAdapter::new()),
    }
}
