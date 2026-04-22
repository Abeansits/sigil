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
        // TODO(adapters): replace with dedicated Codex / OpenCode adapters
        // once their prompt patterns are characterized. Today both silently
        // fall back to ClaudeCodeAdapter — `tool_has_readiness_markers` in
        // tmux.rs skips the readiness poll for these variants so the
        // mis-tuned regex never stalls on launch, but observe/parse paths
        // will report signals against ClaudeCode's shape. Don't treat
        // output signals as authoritative for non-Claude tools.
        ToolKind::Codex => Box::new(ClaudeCodeAdapter::new()),
        ToolKind::OpenCode => Box::new(ClaudeCodeAdapter::new()),
        _ => Box::new(ClaudeCodeAdapter::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Temporary compatibility: `Codex` and `OpenCode` intentionally
    /// alias `ClaudeCodeAdapter` today because their prompt patterns
    /// haven't been characterized yet. `tool_has_readiness_markers` in
    /// `tmux.rs` skips the readiness poll for these variants so the
    /// Claude-specific regex never stalls on launch. This test pins the
    /// intentional aliasing so a future author doesn't assume the
    /// adapter is tuned for those tools — when dedicated adapters land,
    /// this test should be deleted (or flipped to assert non-aliasing).
    #[test]
    fn non_claude_tools_intentionally_alias_claude_adapter() {
        // `ToolAdapter` doesn't expose an identity method today — the
        // structural guarantee is that adapter_for compiles and returns
        // a boxed trait object for every known variant. Compile-time is
        // the strongest assertion here; this test exists as a deliberate
        // marker so the comment above surfaces in test discovery.
        let _ = adapter_for(ToolKind::ClaudeCode);
        let _ = adapter_for(ToolKind::Codex);
        let _ = adapter_for(ToolKind::OpenCode);
    }
}
