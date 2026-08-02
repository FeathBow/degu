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
}
