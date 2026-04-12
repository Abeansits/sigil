//! Project-level configuration parser for `.sigil/config.toml`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::session::{IdentitySpec, LifecycleEvent};

/// Top-level project configuration from `.sigil/config.toml`.
#[derive(Debug, Deserialize, Default)]
pub struct ProjectConfig {
    /// Identity file configuration.
    pub identity: Option<IdentityConfigSection>,

    /// Memory system configuration.
    pub memory: Option<MemoryConfig>,
}

/// Configuration for the memory subsystem (episodic capture and consolidation).
///
/// All fields have sensible defaults. A missing `[memory]` section in
/// `.sigil/config.toml` is equivalent to `MemoryConfig::default()`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryConfig {
    /// Minimum distinct sessions a candidate learning must appear in
    /// before promotion to `LEARNINGS.md`.
    #[serde(default = "default_promotion_threshold")]
    pub promotion_threshold: u32,

    /// Days after which episodes are archived.
    #[serde(default = "default_episode_retention_days")]
    pub episode_retention_days: u32,

    /// Days without reinforcement before a learning is marked stale.
    #[serde(default = "default_staleness_days")]
    pub staleness_days: u32,

    /// Enable episodic capture (append episodes on lifecycle events).
    #[serde(default = "default_true")]
    pub episodes_enabled: bool,

    /// Enable mechanical consolidation in conductor idle loop.
    #[serde(default = "default_true")]
    pub consolidation_enabled: bool,
}

fn default_promotion_threshold() -> u32 {
    3
}
fn default_episode_retention_days() -> u32 {
    90
}
fn default_staleness_days() -> u32 {
    180
}
fn default_true() -> bool {
    true
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            promotion_threshold: 3,
            episode_retention_days: 90,
            staleness_days: 180,
            episodes_enabled: true,
            consolidation_enabled: true,
        }
    }
}

/// The `[identity]` section of `.sigil/config.toml`.
#[derive(Debug, Deserialize)]
pub struct IdentityConfigSection {
    /// Paths relative to the project directory.
    pub files: Vec<PathBuf>,

    /// Lifecycle events that trigger a reload (as strings).
    /// Valid values: `PostCompact`, `PreCompact`, `Restart`, `SessionStart`.
    pub reload_on: Option<Vec<String>>,
}

impl ProjectConfig {
    /// Load project configuration from `.sigil/config.toml` in the given directory.
    ///
    /// Returns `Ok(None)` if the config file does not exist.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidConfig` if the file exists but cannot be
    /// read or contains invalid TOML.
    pub fn load(project_dir: &Path) -> Result<Option<Self>, CoreError> {
        let config_path = project_dir.join(".sigil").join("config.toml");

        let contents = match std::fs::read_to_string(&config_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(CoreError::InvalidConfig {
                    message: format!("failed to read {}: {e}", config_path.display()),
                });
            }
        };

        let config: Self = toml::from_str(&contents).map_err(|e| CoreError::InvalidConfig {
            message: format!("failed to parse {}: {e}", config_path.display()),
        })?;

        Ok(Some(config))
    }
}

/// Parse a string into a `LifecycleEvent`.
fn parse_lifecycle_event(s: &str) -> Result<LifecycleEvent, CoreError> {
    match s {
        "PostCompact" => Ok(LifecycleEvent::PostCompact),
        "PreCompact" => Ok(LifecycleEvent::PreCompact),
        "Restart" => Ok(LifecycleEvent::Restart),
        "SessionStart" => Ok(LifecycleEvent::SessionStart),
        "PostAction" => Ok(LifecycleEvent::PostAction),
        "SessionEnd" => Ok(LifecycleEvent::SessionEnd),
        "Idle" => Ok(LifecycleEvent::Idle),
        _ => Err(CoreError::InvalidConfig {
            message: format!(
                "unknown lifecycle event '{s}' \
                 (expected PostCompact, PreCompact, Restart, SessionStart, \
                 PostAction, SessionEnd, or Idle)"
            ),
        }),
    }
}

impl IdentityConfigSection {
    /// Convert this config section into a validated `IdentitySpec`.
    ///
    /// Validates `reload_on` strings against known `LifecycleEvent` variants.
    /// If `reload_on` is `None`, defaults to `[PostCompact, PreCompact]`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidConfig` if any `reload_on` string is not a
    /// recognized lifecycle event.
    pub fn into_spec(self) -> Result<IdentitySpec, CoreError> {
        let reload_on = match self.reload_on {
            Some(events) => events
                .iter()
                .map(|s| parse_lifecycle_event(s))
                .collect::<Result<Vec<_>, _>>()?,
            None => vec![LifecycleEvent::PostCompact, LifecycleEvent::PreCompact],
        };

        Ok(IdentitySpec {
            files: self.files,
            reload_on,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn parse_valid_config() {
        let toml_str = r#"
[identity]
files = ["SOUL.md", "OPS.md", "state.json"]
reload_on = ["PostCompact", "PreCompact", "Restart"]
"#;

        let config: ProjectConfig = toml::from_str(toml_str).unwrap();
        let section = config.identity.unwrap();
        assert_eq!(section.files.len(), 3);
        assert_eq!(section.files[0], PathBuf::from("SOUL.md"));
        assert_eq!(section.files[1], PathBuf::from("OPS.md"));
        assert_eq!(section.files[2], PathBuf::from("state.json"));

        let reload = section.reload_on.unwrap();
        assert_eq!(reload, vec!["PostCompact", "PreCompact", "Restart"]);
    }

    #[test]
    fn parse_config_missing_identity_section() {
        let toml_str = r#"
[some_other_section]
key = "value"
"#;

        let config: ProjectConfig = toml::from_str(toml_str).unwrap();
        assert!(config.identity.is_none());
    }

    #[test]
    fn parse_empty_config() {
        let config: ProjectConfig = toml::from_str("").unwrap();
        assert!(config.identity.is_none());
    }

    #[test]
    fn into_spec_validates_reload_on() {
        let section = IdentityConfigSection {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: Some(vec!["PostCompact".into(), "Restart".into()]),
        };

        let spec = section.into_spec().unwrap();
        assert_eq!(spec.files, vec![PathBuf::from("SOUL.md")]);
        assert_eq!(spec.reload_on.len(), 2);
        assert_eq!(spec.reload_on[0], LifecycleEvent::PostCompact);
        assert_eq!(spec.reload_on[1], LifecycleEvent::Restart);
    }

    #[test]
    fn into_spec_defaults_reload_on_when_none() {
        let section = IdentityConfigSection {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: None,
        };

        let spec = section.into_spec().unwrap();
        assert_eq!(spec.reload_on.len(), 2);
        assert_eq!(spec.reload_on[0], LifecycleEvent::PostCompact);
        assert_eq!(spec.reload_on[1], LifecycleEvent::PreCompact);
    }

    #[test]
    fn into_spec_rejects_invalid_reload_on() {
        let section = IdentityConfigSection {
            files: vec![PathBuf::from("SOUL.md")],
            reload_on: Some(vec!["PostCompact".into(), "InvalidEvent".into()]),
        };

        let err = section.into_spec().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("InvalidEvent"),
            "error should mention the bad value: {msg}"
        );
    }

    #[test]
    fn load_missing_directory_returns_none() {
        let dir = PathBuf::from("/tmp/sigil-test-nonexistent-dir-29384756");
        let result = ProjectConfig::load(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_valid_config_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let sigil_dir = dir.path().join(".sigil");
        std::fs::create_dir_all(&sigil_dir).unwrap();
        std::fs::write(
            sigil_dir.join("config.toml"),
            r#"
[identity]
files = ["SOUL.md", "OPS.md"]
reload_on = ["PostCompact"]
"#,
        )
        .unwrap();

        let config = ProjectConfig::load(dir.path()).unwrap().unwrap();
        let section = config.identity.unwrap();
        assert_eq!(section.files.len(), 2);

        let spec = section.into_spec().unwrap();
        assert_eq!(spec.reload_on, vec![LifecycleEvent::PostCompact]);
    }

    #[test]
    fn load_config_without_identity_returns_none_section() {
        let dir = tempfile::tempdir().unwrap();
        let sigil_dir = dir.path().join(".sigil");
        std::fs::create_dir_all(&sigil_dir).unwrap();
        std::fs::write(sigil_dir.join("config.toml"), "# empty config\n").unwrap();

        let config = ProjectConfig::load(dir.path()).unwrap().unwrap();
        assert!(config.identity.is_none());
    }

    #[test]
    fn load_malformed_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let sigil_dir = dir.path().join(".sigil");
        std::fs::create_dir_all(&sigil_dir).unwrap();
        std::fs::write(sigil_dir.join("config.toml"), "[identity\nbroken").unwrap();

        let result = ProjectConfig::load(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn parse_all_lifecycle_events() {
        assert_eq!(
            parse_lifecycle_event("PostCompact").unwrap(),
            LifecycleEvent::PostCompact
        );
        assert_eq!(
            parse_lifecycle_event("PreCompact").unwrap(),
            LifecycleEvent::PreCompact
        );
        assert_eq!(
            parse_lifecycle_event("Restart").unwrap(),
            LifecycleEvent::Restart
        );
        assert_eq!(
            parse_lifecycle_event("SessionStart").unwrap(),
            LifecycleEvent::SessionStart
        );
    }

    #[test]
    fn parse_lifecycle_event_case_sensitive() {
        assert!(parse_lifecycle_event("postcompact").is_err());
        assert!(parse_lifecycle_event("POSTCOMPACT").is_err());
        assert!(parse_lifecycle_event("post_compact").is_err());
    }

    // -- New lifecycle event variants -----------------------------------------

    #[test]
    fn parse_new_lifecycle_events() {
        assert_eq!(
            parse_lifecycle_event("PostAction").unwrap(),
            LifecycleEvent::PostAction
        );
        assert_eq!(
            parse_lifecycle_event("SessionEnd").unwrap(),
            LifecycleEvent::SessionEnd
        );
        assert_eq!(parse_lifecycle_event("Idle").unwrap(), LifecycleEvent::Idle);
    }

    #[test]
    fn new_lifecycle_events_in_config() {
        let toml_str = r#"
[identity]
files = ["SOUL.md"]
reload_on = ["PostCompact", "PostAction", "SessionEnd", "Idle"]
"#;

        let config: ProjectConfig = toml::from_str(toml_str).unwrap();
        let section = config.identity.unwrap();
        let spec = section.into_spec().unwrap();
        assert_eq!(spec.reload_on.len(), 4);
        assert_eq!(spec.reload_on[0], LifecycleEvent::PostCompact);
        assert_eq!(spec.reload_on[1], LifecycleEvent::PostAction);
        assert_eq!(spec.reload_on[2], LifecycleEvent::SessionEnd);
        assert_eq!(spec.reload_on[3], LifecycleEvent::Idle);
    }

    // -- MemoryConfig ---------------------------------------------------------

    #[test]
    fn memory_config_default_values() {
        let config = MemoryConfig::default();
        assert_eq!(config.promotion_threshold, 3);
        assert_eq!(config.episode_retention_days, 90);
        assert_eq!(config.staleness_days, 180);
        assert!(config.episodes_enabled);
        assert!(config.consolidation_enabled);
    }

    #[test]
    fn memory_config_serde_round_trip() {
        let config = MemoryConfig {
            promotion_threshold: 5,
            episode_retention_days: 60,
            staleness_days: 120,
            episodes_enabled: false,
            consolidation_enabled: true,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: MemoryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn parse_memory_section_from_toml() {
        let toml_str = r"
[memory]
promotion_threshold = 5
episode_retention_days = 60
staleness_days = 120
episodes_enabled = false
consolidation_enabled = true
";

        let config: ProjectConfig = toml::from_str(toml_str).unwrap();
        let memory = config.memory.unwrap();
        assert_eq!(memory.promotion_threshold, 5);
        assert_eq!(memory.episode_retention_days, 60);
        assert_eq!(memory.staleness_days, 120);
        assert!(!memory.episodes_enabled);
        assert!(memory.consolidation_enabled);
    }

    #[test]
    fn missing_memory_section_returns_none() {
        let toml_str = r#"
[identity]
files = ["SOUL.md"]
"#;

        let config: ProjectConfig = toml::from_str(toml_str).unwrap();
        assert!(config.memory.is_none());
    }

    #[test]
    fn memory_section_with_defaults() {
        let toml_str = r"
[memory]
";

        let config: ProjectConfig = toml::from_str(toml_str).unwrap();
        let memory = config.memory.unwrap();
        assert_eq!(memory, MemoryConfig::default());
    }

    #[test]
    fn memory_section_partial_override() {
        let toml_str = r"
[memory]
promotion_threshold = 10
";

        let config: ProjectConfig = toml::from_str(toml_str).unwrap();
        let memory = config.memory.unwrap();
        assert_eq!(memory.promotion_threshold, 10);
        // Other fields should be defaults.
        assert_eq!(memory.episode_retention_days, 90);
        assert_eq!(memory.staleness_days, 180);
        assert!(memory.episodes_enabled);
        assert!(memory.consolidation_enabled);
    }
}
