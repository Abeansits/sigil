pub mod claude_code;

use ops_core::session::ToolKind;
use ops_core::traits::ToolAdapter;

use self::claude_code::ClaudeCodeAdapter;

/// Return the appropriate adapter for the given tool kind.
///
/// All tool kinds currently use the `ClaudeCodeAdapter`. As dedicated
/// adapters are implemented (e.g. Codex), this function will dispatch
/// to them.
#[allow(clippy::match_same_arms, clippy::wildcard_enum_match_arm)]
pub fn adapter_for(tool: ToolKind) -> Box<dyn ToolAdapter> {
    match tool {
        ToolKind::ClaudeCode => Box::new(ClaudeCodeAdapter::new()),
        ToolKind::Codex => Box::new(ClaudeCodeAdapter::new()),
        _ => Box::new(ClaudeCodeAdapter::new()),
    }
}
