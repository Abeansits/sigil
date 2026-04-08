//! TOML-based tool configuration.
//!
//! Each tool entry specifies the command binary, adapter name, and an
//! optional list of skill directories that get passed to the tool at
//! launch.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::RuntimeError;

/// Root tool configuration loaded from a TOML file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolConfig {
    pub tools: HashMap<String, ToolEntry>,
}

/// A single tool entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolEntry {
    /// Binary name or path (e.g. `"claude"`, `"codex"`).
    pub command: String,
    /// Adapter key used by the runtime (e.g. `"claude-code"`, `"codex"`).
    pub adapter: String,
    /// Skill directories attached to this tool at launch.
    #[serde(default)]
    pub skills: Vec<PathBuf>,
}

impl ToolConfig {
    /// Load a `ToolConfig` from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, RuntimeError> {
        let content = std::fs::read_to_string(path).map_err(|e| RuntimeError::ConfigLoad {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        Self::from_toml(&content)
    }

    /// Parse a `ToolConfig` from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if parsing fails.
    pub fn from_toml(content: &str) -> Result<Self, RuntimeError> {
        toml::from_str(content).map_err(|e| RuntimeError::ConfigParse {
            message: e.to_string(),
        })
    }

    /// Sensible defaults: Claude Code and Codex with no skills.
    #[must_use]
    pub fn default_config() -> Self {
        let mut tools = HashMap::new();

        tools.insert(
            "claude".to_owned(),
            ToolEntry {
                command: "claude".to_owned(),
                adapter: "claude-code".to_owned(),
                skills: Vec::new(),
            },
        );

        tools.insert(
            "codex".to_owned(),
            ToolEntry {
                command: "codex".to_owned(),
                adapter: "codex".to_owned(),
                skills: Vec::new(),
            },
        );

        Self { tools }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn default_config_has_claude_and_codex() {
        let config = ToolConfig::default_config();
        assert!(config.tools.contains_key("claude"), "missing claude entry");
        assert!(config.tools.contains_key("codex"), "missing codex entry");
        assert_eq!(config.tools.len(), 2);
    }

    #[test]
    fn default_config_claude_entry_is_correct() {
        let config = ToolConfig::default_config();
        let claude = config.tools.get("claude").expect("missing claude");
        assert_eq!(claude.command, "claude");
        assert_eq!(claude.adapter, "claude-code");
        assert!(claude.skills.is_empty());
    }

    #[test]
    fn default_config_codex_entry_is_correct() {
        let config = ToolConfig::default_config();
        let codex = config.tools.get("codex").expect("missing codex");
        assert_eq!(codex.command, "codex");
        assert_eq!(codex.adapter, "codex");
        assert!(codex.skills.is_empty());
    }

    #[test]
    fn from_toml_parses_valid_config() {
        let toml_str = r#"
[tools.claude]
command = "claude"
adapter = "claude-code"
skills = ["/home/user/.skills/review"]

[tools.codex]
command = "codex"
adapter = "codex"
skills = []
"#;
        let config = ToolConfig::from_toml(toml_str);
        assert!(config.is_ok(), "parse failed: {config:?}");
        let config = config.expect("should parse");
        assert_eq!(config.tools.len(), 2);

        let claude = config.tools.get("claude").expect("missing claude");
        assert_eq!(claude.skills.len(), 1);
        assert_eq!(claude.skills[0], PathBuf::from("/home/user/.skills/review"),);
    }

    #[test]
    fn from_toml_with_invalid_content_returns_error() {
        let result = ToolConfig::from_toml("not valid { toml");
        assert!(result.is_err());
    }

    #[test]
    fn load_missing_file_returns_error() {
        let result = ToolConfig::load(Path::new("/nonexistent/path/tools.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn from_toml_with_skills_omitted_defaults_to_empty() {
        let toml_str = r#"
[tools.claude]
command = "claude"
adapter = "claude-code"
"#;
        let config = ToolConfig::from_toml(toml_str).expect("should parse");
        let claude = config.tools.get("claude").expect("missing claude");
        assert!(claude.skills.is_empty());
    }

    #[test]
    fn from_toml_with_multiple_skills() {
        let toml_str = r#"
[tools.claude]
command = "claude"
adapter = "claude-code"
skills = ["/skills/a", "/skills/b", "/skills/c"]
"#;
        let config = ToolConfig::from_toml(toml_str).expect("should parse");
        let claude = config.tools.get("claude").expect("missing claude");
        assert_eq!(claude.skills.len(), 3);
    }
}
