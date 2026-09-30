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

/// Plant one extended attribute of a class this platform's staging admits, which is
/// what a filesystem that attaches provenance to every written file leaves behind.
#[allow(
    dead_code,
    reason = "shared support is compiled into integration-test crates that use different helpers"
)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn set_ordinary_xattr(path: &Path, value: &[u8]) {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path).unwrap();
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"user.degu-proof-v3".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"com.apple.quarantine".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    assert_eq!(
        result,
        0,
        "failed to set ordinary xattr: {}",
        std::io::Error::last_os_error()
    );
}

/// Remove every extended attribute from each regular file under `root`.
///
/// A sealed purge refuses a staged tree whose regular files carry any extended
/// attribute at all -- not only one its staging allowlist would decline -- and some
/// filesystems attach one to every file a process writes, macOS provenance among
/// them. A fixture that stages regular files and then purges them is otherwise
/// measuring the host rather than degu, and fails on the machines that do.
///
/// Symlinks are left alone: they are not what the purge inventory classifies here.
#[allow(
    dead_code,
    reason = "shared support is compiled into integration-test crates that use different helpers"
)]
pub fn strip_extended_attributes(root: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(root)? {
            strip_extended_attributes(&entry?.path())?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Ok(());
    }
    let file = std::fs::File::open(root)?;
    for name in extended_attribute_names(&file)? {
        remove_extended_attribute(&file, &name)?;
    }
    Ok(())
}

#[allow(dead_code, reason = "used only by strip_extended_attributes")]
fn extended_attribute_names(file: &std::fs::File) -> std::io::Result<Vec<std::ffi::CString>> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    // Asked for a size first, then read: the set can change between the two, and a
    // buffer sized from a stale answer would silently truncate the list.
    let size = unsafe {
        #[cfg(target_os = "linux")]
        let size = libc::flistxattr(fd, std::ptr::null_mut(), 0);
        #[cfg(target_os = "macos")]
        let size = libc::flistxattr(fd, std::ptr::null_mut(), 0, 0);
        size
    };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0i8; size as usize];
    let written = unsafe {
        #[cfg(target_os = "linux")]
        let written = libc::flistxattr(fd, buffer.as_mut_ptr(), buffer.len());
        #[cfg(target_os = "macos")]
        let written = libc::flistxattr(fd, buffer.as_mut_ptr(), buffer.len(), 0);
        written
    };
    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bytes = buffer[..written as usize]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| std::ffi::CString::new(name).expect("a listed xattr name has no interior nul"))
        .collect())
}

#[allow(dead_code, reason = "used only by strip_extended_attributes")]
fn remove_extended_attribute(file: &std::fs::File, name: &std::ffi::CStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let result = unsafe {
        #[cfg(target_os = "linux")]
        let result = libc::fremovexattr(file.as_raw_fd(), name.as_ptr());
        #[cfg(target_os = "macos")]
        let result = libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0);
        result
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        // A name listed a moment ago may be gone, and some are not removable by
        // the owner at all; neither leaves an attribute this fixture put there.
        // Linux spells the missing-attribute error `ENODATA`.
        #[cfg(target_os = "linux")]
        let absent = libc::ENODATA;
        #[cfg(target_os = "macos")]
        let absent = libc::ENOATTR;
        if matches!(error.raw_os_error(), Some(code) if code == absent || code == libc::EPERM) {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
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

#[allow(
    dead_code,
    reason = "shared support is compiled into integration-test crates that use different helpers"
)]
pub fn isolated_degu() -> Command {
    // The test-built binary recognizes a dev-feature-only anchor variable. The
    // wrapper derives it from each test's eventual XDG state at child startup;
    // release binaries compile without that feature and ignore the variable.
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(
            r#"if [ -n "$XDG_STATE_HOME" ]; then
                 anchor="$XDG_STATE_HOME/degu-integration-activation-anchor"
                 /bin/mkdir -p "$anchor" || exit
                 /bin/chmod 700 "$anchor" || exit
                 anchor=$(cd "$anchor" && pwd -P) || exit
                 export DEGU_INTEGRATION_TEST_ANCHOR="$anchor"
                 export DEGU_INTEGRATION_TEST_LEGACY_CLEAN=1
               fi
               for p in "$HOME" "$XDG_STATE_HOME"; do
                 if [ -n "$p" ] && [ -d "$p" ]; then /bin/chmod go-w "$p" || exit; fi
               done
               exec "$0" "$@""#,
        )
        .arg(assert_cmd::cargo::cargo_bin("degu"));
    command.env_clear();
    command.env("LOGNAME", isolated_config_home());
    command.env("XDG_CONFIG_HOME", isolated_config_home());
    command
}

/// Provision the integration-test-only activation anchor beside this command's
/// isolated state. The release dependency does not enable the core feature that
/// recognizes this variable, and `degu doctor` always ignores it.
#[allow(
    dead_code,
    reason = "shared support is compiled into integration-test crates that do not mutate"
)]
pub fn with_mutation_anchor(command: &mut Command, state: &Path) {
    let anchor = state.join("degu-integration-activation-anchor");
    std::fs::create_dir_all(&anchor).unwrap();
    std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
    command.env(
        "DEGU_INTEGRATION_TEST_ANCHOR",
        std::fs::canonicalize(anchor).unwrap(),
    );
    command.env("DEGU_INTEGRATION_TEST_LEGACY_CLEAN", "1");
}

#[allow(
    dead_code,
    reason = "shared support is compiled into integration-test crates that use different helpers"
)]
pub fn certify_backend(
    path: &std::path::Path,
) -> Result<degu_core::backend::CertifiedLocalBackend, degu_core::backend::CertificationError> {
    let directory = std::fs::File::open(path)
        .map_err(|_| degu_core::backend::CertificationError::InspectionFailed)?;
    degu_core::backend::certify_held_fd_backend(&directory)
}

/// Sealed-admission fixtures require a certified backend. Linux may skip only
/// an unsupported fixture filesystem; macOS asserts APFS so coverage cannot
/// silently vanish; every other failure is a test failure.
#[allow(
    dead_code,
    reason = "shared support is compiled into integration-test crates that use different helpers"
)]
pub fn require_sealed_fixture_backend(
    path: &std::path::Path,
) -> Option<degu_core::backend::CertifiedLocalBackend> {
    match certify_backend(path) {
        Ok(backend) => {
            #[cfg(target_os = "macos")]
            assert_eq!(
                backend,
                degu_core::backend::CertifiedLocalBackend::Apfs,
                "macOS sealed fixtures must execute on APFS"
            );
            Some(backend)
        }
        #[cfg(target_os = "linux")]
        Err(
            degu_core::backend::CertificationError::UnsupportedFilesystem
            | degu_core::backend::CertificationError::UnsupportedPlatform,
        ) => {
            eprintln!(
                "skipping sealed fixture: uncertified filesystem at {}",
                path.display()
            );
            None
        }
        Err(error) => panic!("sealed fixture certification failed: {error:?}"),
    }
}
