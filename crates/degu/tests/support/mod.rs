use assert_cmd::Command;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[allow(
    dead_code,
    reason = "shared support is compiled into integration-test crates that use different helpers"
)]
pub fn make_tree_non_shared_writable(root: &Path) -> std::io::Result<()> {
    fn strip_dir_write(dir: &Path) -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(());
        }
        let mode = metadata.permissions().mode();
        let hardened = mode & !0o022;
        if hardened != mode {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(hardened))?;
        }
        for entry in std::fs::read_dir(dir)? {
            strip_dir_write(&entry?.path())?;
        }
        Ok(())
    }
    strip_dir_write(root)
}

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
