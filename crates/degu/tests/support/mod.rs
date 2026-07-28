use assert_cmd::Command;
use std::path::{Path, PathBuf};

/// The cache dir the adapters probe for `name` on the current platform, matching
/// `degu_adapters::platform_cache_root`: `Library/Caches` on macOS, `.cache` else.
/// Fixtures seed here so a scan finds them without relying on the old dual probe.
#[allow(dead_code)]
pub fn platform_cache_dir(home: &Path, name: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Caches").join(name)
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join(".cache").join(name)
    }
}

pub fn isolated_config_home() -> &'static Path {
    static CONFIG_HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    CONFIG_HOME
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("degu")).unwrap();
            std::fs::write(dir.path().join("degu/config.toml"), "").unwrap();
            dir
        })
        .path()
}

pub fn isolated_degu() -> Command {
    let mut command = Command::cargo_bin("degu").unwrap();
    command.env_clear();
    command.env("LOGNAME", isolated_config_home());
    command.env("XDG_CONFIG_HOME", isolated_config_home());
    command
}
