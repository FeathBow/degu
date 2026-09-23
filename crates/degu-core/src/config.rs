use serde::Deserialize;
use std::num::NonZeroUsize;

/// Hard ceiling for user-configured walker threads. A larger value can spend
/// substantial CPU and address space creating threads before any scan work.
pub const MAX_SCAN_CONCURRENCY: usize = 256;

/// User config (~/.config/degu/config.toml). May add read-only coverage or
/// protection, or disable ecosystems; no field may loosen deletion authority.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Extra protected paths (relative to $HOME), merged into the Guard
    pub protect: Vec<String>,
    /// Project roots searched only by read-only scan commands
    pub roots: Vec<String>,
    /// Disabled adapter ids; everything else is on by default
    pub disable: Vec<String>,
    /// Upper bound on concurrent directory reads
    pub max_concurrency: Option<NonZeroUsize>,
    /// Opt scan into node-runtime diagnostics (the shm and tmp adapters);
    /// clean never enables them regardless of this key
    pub runtime: bool,
    /// The advisory pane, and the external advisor that fills its unverified
    /// layer. Display only: no key here can change a disposition or a plan.
    pub advisory: AdvisoryConfig,
}

/// Seconds an advisor may take before degu stops waiting for it.
pub const DEFAULT_ADVISORY_TIMEOUT_SECONDS: u64 = 20;
pub const MAX_ADVISORY_TIMEOUT_SECONDS: u64 = 120;

/// Decision support shown beside a finding, never part of one.
///
/// degu speaks no model protocol and holds no credential. `command` names an
/// executable the account already trusts; degu hands it a signature and reads
/// back prose, under the same bounds every other host tool runs under. Which
/// model, which endpoint and which key are entirely that program's business,
/// and degu cannot learn any of them: the child's environment is emptied, so a
/// credential cannot even be passed through.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AdvisoryConfig {
    /// The pane is shown unless this is false. What it can show depends on what
    /// is available: measured facts always, an external advisory only when
    /// `command` is set.
    pub enabled: bool,
    /// Absolute path to the advisor. Absent means no external advisory; the
    /// pane still reports what degu measured.
    pub command: Option<String>,
    /// Seconds the advisor may take.
    pub timeout_seconds: u64,
}

impl Default for AdvisoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            command: None,
            timeout_seconds: DEFAULT_ADVISORY_TIMEOUT_SECONDS,
        }
    }
}

impl Config {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fields_are_rejected() {
        // A silently-ignored typo in an authority-related config is worse than an error.
        assert!(Config::from_toml("allow_root = true").is_err());
    }

    #[test]
    fn zero_max_concurrency_is_rejected() {
        let error = Config::from_toml("max_concurrency = 0").unwrap_err();
        assert!(error.to_string().contains("nonzero"));
    }

    /// The pane exists without being asked for. A reader who never edits this
    /// file still gets told when degu could not classify something, and what
    /// would let them find out more.
    #[test]
    fn the_advisory_pane_is_on_without_a_config() {
        let config = Config::from_toml("").expect("an empty config");
        assert!(config.advisory.enabled);
        assert_eq!(config.advisory.command, None);
    }

    /// Being on is not the same as consulting anybody. Without a command degu
    /// runs no program and sends nothing anywhere, which is what an untouched
    /// install must do on a login node.
    #[test]
    fn an_enabled_advisory_consults_nobody_by_default() {
        assert_eq!(Config::default().advisory.command, None);
    }

    #[test]
    fn an_advisory_typo_is_rejected_rather_than_ignored() {
        assert!(Config::from_toml("[advisory]\nenable = true").is_err());
    }
}
