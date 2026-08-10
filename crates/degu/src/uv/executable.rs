//! Bounded, descriptor-bound uv version probe.
//!
//! The command owner supplies the lexical path. Before executing any bytes from
//! it, this module rejects foreign-writable namespace components, foreign-owned
//! symlinks, unsafe file ownership/mode, extended ACLs, and non-native binaries.
//! The selected object is pinned by descriptor and copied once into a bounded,
//! private native-binary snapshot. The version probe and any later native action
//! execute that same snapshot, so pathname replacement cannot exchange the
//! probed executable for a different cleanup executable. Snapshot cleanup is
//! restricted to fixed names below exact held directory descriptors.

use crate::native::{
    HeldNativeExecutable, NativePreparationError, NativeRunOutcome, NativeRunnerError,
    PreparedNativeAction, cleanup_executable_snapshot, prepare_native_action_from_held,
    prepare_native_action_from_held_with_binding,
};
use degu_adapters::native::{
    NativeActionIdentity, NativeActionRequest, NativeEnvironmentRequest, NativeExecutableSelection,
    NativeProcessContract,
};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags};
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_OUTPUT_LIMIT: usize = 128;
const MINIMUM_UV_VERSION: UvVersion = UvVersion::new(0, 8, 19);
/// The only cache-prune layout whose exact traversal and mutation contract is
/// audited. A newer binary may pass the minimum-version probe, but native
/// authority must remain unavailable until that version's prune implementation
/// is separately audited.
pub(crate) const AUDITED_UV_PRUNE_VERSION: UvVersion = UvVersion::new(0, 12, 3);
const SHARED_WRITE_MASK: u32 = 0o022;
const EXECUTE_MASK: u32 = 0o111;
const MAX_XATTR_LIST_BYTES: usize = 64 * 1024;
const MAX_EXECUTABLE_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct UvVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl UvVersion {
    pub(crate) const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for UvVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Unforgeable within the CLI crate: owns the exact object that answered the
/// bounded version probe. It is intentionally neither public nor cloneable.
pub(crate) struct ProbedUvExecutable {
    selection: NativeExecutableSelection,
    canonical_path: PathBuf,
    identity: ExecutableIdentity,
    /// Pins the originally selected object so its inode cannot be reused while
    /// path attachment is revalidated.
    source_executable: OwnedFd,
    /// Private byte-for-byte snapshot used by both probe and later action. A
    /// stable private path is required because macOS cannot exec `/dev/fd/N`.
    executable: HeldNativeExecutable,
    version: UvVersion,
}

impl ProbedUvExecutable {
    pub(crate) fn selection(&self) -> &NativeExecutableSelection {
        &self.selection
    }

    pub(crate) fn version(&self) -> UvVersion {
        self.version
    }

    /// Re-resolve the reviewed path and require it still to name the held
    /// object. The held object prevents inode reuse while this proof exists.
    pub(crate) fn revalidate_path(&self) -> Result<(), UvExecutableProbeError> {
        let source_stat = rustix::fs::fstat(&self.source_executable)
            .map_err(|source| inspect(self.selection.as_path(), io::Error::from(source)))?;
        let pinned_identity = executable_identity(&source_stat, &self.canonical_path)?;
        let current = open_selected_executable(&self.selection)?;
        if pinned_identity != self.identity
            || current.canonical_path != self.canonical_path
            || current.identity != self.identity
        {
            return Err(UvExecutableProbeError::PathChanged);
        }
        Ok(())
    }

    /// Consume the exact snapshot that answered the version probe into one
    /// runner action. No held descriptor or reusable split capability escapes
    /// this module.
    pub(crate) fn into_native_action_with_binding(
        self,
        request: NativeActionRequest,
        mutation_binding: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<PreparedNativeAction, NativePreparationError> {
        prepare_native_action_from_held_with_binding(request, self.executable, mutation_binding)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
    size: u64,
}

struct OpenedExecutable {
    canonical_path: PathBuf,
    identity: ExecutableIdentity,
    executable: OwnedFd,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UvExecutableProbeError {
    #[error("failed to inspect selected uv executable at {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("selected uv executable path is unsafe at {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: &'static str },
    #[error("failed to inspect extended ACLs at {path}: {source}")]
    AclInspection {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect extended attributes at {path}: {source}")]
    XattrInspection {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("selected uv executable at {0} is not an ELF or Mach-O native binary")]
    NotNativeBinary(PathBuf),
    #[error("failed to prepare bounded uv version probe: {0}")]
    Preparation(#[from] NativePreparationError),
    #[error("bounded uv version probe failed to run: {0}")]
    Runner(#[from] NativeRunnerError),
    #[error("uv version probe exited unsuccessfully with code {code:?}")]
    ExitFailure { code: Option<i32> },
    #[error("uv version probe terminated by signal {signal:?}")]
    Signal { signal: Option<i32> },
    #[error("uv version probe exceeded its two-second timeout")]
    Timeout,
    #[error("uv version probe output exceeded its 128-byte bound")]
    OutputTruncated,
    #[error("uv version output is invalid: {0}")]
    InvalidOutput(UvVersionParseError),
    #[error("uv {found} is older than the required minimum {minimum}")]
    VersionTooOld {
        found: UvVersion,
        minimum: UvVersion,
    },
    #[error("selected uv executable path changed during or after its version probe")]
    PathChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UvVersionParseError {
    #[error("output is not UTF-8")]
    NotUtf8,
    #[error("expected exactly `uv MAJOR.MINOR.PATCH` followed by one newline")]
    InvalidShape,
    #[error("version component is empty, non-decimal, non-canonical, or overflowing")]
    InvalidComponent,
}

pub(crate) fn probe_uv_executable(
    selection: NativeExecutableSelection,
) -> Result<ProbedUvExecutable, UvExecutableProbeError> {
    probe_uv_executable_with(
        selection,
        [OsString::from("-V")],
        NativeEnvironmentRequest::clear(),
        &mut || {},
    )
}

fn probe_uv_executable_with(
    selection: NativeExecutableSelection,
    arguments: impl IntoIterator<Item = OsString>,
    environment: NativeEnvironmentRequest,
    after_probe: &mut impl FnMut(),
) -> Result<ProbedUvExecutable, UvExecutableProbeError> {
    let opened = open_selected_executable(&selection)?;
    let executable = snapshot_executable(&opened)?;
    require_source_unchanged(&opened)?;
    let probe_executable =
        executable
            .duplicate()
            .map_err(|source| UvExecutableProbeError::Inspect {
                path: selection.as_path().to_path_buf(),
                source,
            })?;
    let request = NativeActionRequest::new(
        NativeActionIdentity::new("uv", "version-probe")
            .expect("static uv probe identity is valid"),
        selection.clone(),
        arguments,
        environment,
        NativeProcessContract::AuditedCooperativeProcessGroup,
        VERSION_PROBE_TIMEOUT,
        VERSION_OUTPUT_LIMIT,
        VERSION_OUTPUT_LIMIT,
        [],
    )
    .expect("static uv probe declaration is bounded");
    let report = prepare_native_action_from_held(request, probe_executable)?
        .execute(parse_uv_version)
        .result()?;
    let version = match report.outcome() {
        NativeRunOutcome::Success(version) => *version,
        NativeRunOutcome::ExitFailure { code } => {
            return Err(UvExecutableProbeError::ExitFailure { code: *code });
        }
        NativeRunOutcome::Signal { signal } => {
            return Err(UvExecutableProbeError::Signal { signal: *signal });
        }
        NativeRunOutcome::Timeout => return Err(UvExecutableProbeError::Timeout),
        NativeRunOutcome::OutputTruncated => {
            return Err(UvExecutableProbeError::OutputTruncated);
        }
        NativeRunOutcome::OutputParseFailure(error) => {
            return Err(UvExecutableProbeError::InvalidOutput(*error));
        }
    };
    if version < MINIMUM_UV_VERSION {
        return Err(UvExecutableProbeError::VersionTooOld {
            found: version,
            minimum: MINIMUM_UV_VERSION,
        });
    }

    after_probe();
    let current = open_selected_executable(&selection)?;
    if current.canonical_path != opened.canonical_path || current.identity != opened.identity {
        return Err(UvExecutableProbeError::PathChanged);
    }
    Ok(ProbedUvExecutable {
        selection,
        canonical_path: opened.canonical_path,
        identity: opened.identity,
        source_executable: opened.executable,
        executable,
        version,
    })
}

fn require_source_unchanged(source: &OpenedExecutable) -> Result<(), UvExecutableProbeError> {
    let current = rustix::fs::fstat(&source.executable)
        .map_err(|error| inspect(&source.canonical_path, io::Error::from(error)))?;
    if executable_identity(&current, &source.canonical_path)? != source.identity {
        return Err(UvExecutableProbeError::PathChanged);
    }
    Ok(())
}

fn validate_snapshot_parent_chain(temp: &Path) -> Result<(), UvExecutableProbeError> {
    if !temp.is_absolute() {
        return Err(unsafe_path(temp, "temporary directory is not absolute"));
    }
    validate_namespace_chain(&temp.join("degu-snapshot-placeholder"), true)?;
    let canonical = std::fs::canonicalize(temp).map_err(|source| inspect(temp, source))?;
    validate_namespace_chain(&canonical.join("degu-snapshot-placeholder"), true)
}

fn snapshot_executable(
    source: &OpenedExecutable,
) -> Result<HeldNativeExecutable, UvExecutableProbeError> {
    if source.identity.size > MAX_EXECUTABLE_SNAPSHOT_BYTES {
        return Err(unsafe_path(
            &source.canonical_path,
            "executable exceeds the 256 MiB snapshot bound",
        ));
    }
    let temp = std::env::temp_dir();
    validate_snapshot_parent_chain(&temp)?;
    let mut guard = create_snapshot_directory(&temp)?;
    let execution_path = guard.path.join("uv");
    let writer = rustix::fs::openat(
        guard.directory(),
        "uv",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    copy_exact_bytes(
        &source.executable,
        &writer,
        source.identity.size,
        &execution_path,
    )?;
    rustix::fs::fchmod(&writer, Mode::from_raw_mode(0o500))
        .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    rustix::fs::fsync(&writer)
        .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    drop(writer);

    let executable = rustix::fs::openat(
        guard.directory(),
        "uv",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    let stat = rustix::fs::fstat(&executable)
        .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    reject_extended_acl(&executable, &execution_path)?;
    reject_unpreserved_xattrs(&executable, &execution_path)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || raw_mode_u32(stat.st_mode) & 0o777 != 0o500
        || u64::try_from(stat.st_size).ok() != Some(source.identity.size)
    {
        return Err(unsafe_path(
            &execution_path,
            "private executable snapshot failed mode, kind, or size verification",
        ));
    }
    let (parent, directory, directory_name) = guard.disarm();
    HeldNativeExecutable::new(
        executable,
        execution_path.clone(),
        parent,
        directory,
        directory_name,
    )
    .map_err(|source| inspect(&execution_path, source))
}

struct SnapshotDirectoryGuard {
    parent: Option<OwnedFd>,
    directory: Option<OwnedFd>,
    directory_name: OsString,
    path: PathBuf,
    armed: bool,
}

impl SnapshotDirectoryGuard {
    fn directory(&self) -> &OwnedFd {
        self.directory
            .as_ref()
            .expect("snapshot directory is armed")
    }

    fn disarm(&mut self) -> (OwnedFd, OwnedFd, OsString) {
        self.armed = false;
        (
            self.parent.take().expect("snapshot parent is armed"),
            self.directory.take().expect("snapshot directory is armed"),
            self.directory_name.clone(),
        )
    }
}

impl Drop for SnapshotDirectoryGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let (Some(parent), Some(directory)) = (&self.parent, &self.directory) {
            cleanup_executable_snapshot(parent, directory, &self.directory_name);
        }
    }
}

fn create_snapshot_directory(
    temp: &Path,
) -> Result<SnapshotDirectoryGuard, UvExecutableProbeError> {
    let parent = rustix::fs::openat(
        rustix::fs::CWD,
        temp,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(temp, io::Error::from(source)))?;
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|source| UvExecutableProbeError::Inspect {
            path: temp.to_path_buf(),
            source: io::Error::other(source),
        })?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            use fmt::Write as _;
            write!(&mut suffix, "{byte:02x}").expect("writing to String cannot fail");
        }
        let directory_name = OsString::from(format!("degu-uv-exec-{suffix}"));
        let path = temp.join(&directory_name);
        match rustix::fs::mkdirat(&parent, &directory_name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                let directory = rustix::fs::openat(
                    &parent,
                    &directory_name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|source| inspect(&path, io::Error::from(source)))?;
                rustix::fs::fchmod(&directory, Mode::from_raw_mode(0o700))
                    .map_err(|source| inspect(&path, io::Error::from(source)))?;
                reject_extended_acl(&directory, &path)?;
                reject_unpreserved_xattrs(&directory, &path)?;
                return Ok(SnapshotDirectoryGuard {
                    parent: Some(parent),
                    directory: Some(directory),
                    directory_name,
                    path,
                    armed: true,
                });
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(source) => return Err(inspect(&path, io::Error::from(source))),
        }
    }
    Err(UvExecutableProbeError::Inspect {
        path: temp.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique private executable snapshot directory",
        ),
    })
}

fn copy_exact_bytes(
    source: &OwnedFd,
    destination: &OwnedFd,
    expected: u64,
    path: &Path,
) -> Result<(), UvExecutableProbeError> {
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while offset < expected {
        let remaining = usize::try_from(
            (expected - offset).min(u64::try_from(buffer.len()).expect("buffer length fits u64")),
        )
        .expect("bounded chunk length fits usize");
        let read = pread(source, &mut buffer[..remaining], offset)
            .map_err(|source| inspect(path, source))?;
        if read == 0 {
            return Err(unsafe_path(
                path,
                "executable shrank while being snapshotted",
            ));
        }
        write_all(destination, &buffer[..read]).map_err(|source| inspect(path, source))?;
        offset += u64::try_from(read).expect("read length fits u64");
    }
    let mut trailing = [0_u8; 1];
    if pread(source, &mut trailing, expected).map_err(|source| inspect(path, source))? != 0 {
        return Err(unsafe_path(path, "executable grew while being snapshotted"));
    }
    Ok(())
}

fn pread(fd: &OwnedFd, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    loop {
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| io::Error::other("executable offset exceeds platform range"))?;
        // SAFETY: `fd` stays live and `buffer` is a valid writable allocation.
        let result = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                offset,
            )
        };
        if result >= 0 {
            return usize::try_from(result).map_err(|_| io::Error::other("read size overflow"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn write_all(fd: &OwnedFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snapshot write returned zero",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(rustix::io::Errno::INTR) => {}
            Err(source) => return Err(io::Error::from(source)),
        }
    }
    Ok(())
}

fn parse_uv_version(stdout: &[u8]) -> Result<UvVersion, UvVersionParseError> {
    let output = std::str::from_utf8(stdout).map_err(|_| UvVersionParseError::NotUtf8)?;
    let body = output
        .strip_suffix('\n')
        .ok_or(UvVersionParseError::InvalidShape)?;
    if body.contains(['\n', '\r']) {
        return Err(UvVersionParseError::InvalidShape);
    }
    let version = body
        .strip_prefix("uv ")
        .ok_or(UvVersionParseError::InvalidShape)?;
    let mut components = version.split('.');
    let major = parse_version_component(components.next())?;
    let minor = parse_version_component(components.next())?;
    let patch = parse_version_component(components.next())?;
    if components.next().is_some() {
        return Err(UvVersionParseError::InvalidShape);
    }
    Ok(UvVersion {
        major,
        minor,
        patch,
    })
}

fn parse_version_component(component: Option<&str>) -> Result<u64, UvVersionParseError> {
    let component = component.ok_or(UvVersionParseError::InvalidShape)?;
    if component.is_empty()
        || !component.bytes().all(|byte| byte.is_ascii_digit())
        || (component.len() > 1 && component.starts_with('0'))
    {
        return Err(UvVersionParseError::InvalidComponent);
    }
    component
        .parse()
        .map_err(|_| UvVersionParseError::InvalidComponent)
}

fn open_selected_executable(
    selection: &NativeExecutableSelection,
) -> Result<OpenedExecutable, UvExecutableProbeError> {
    let selected = selection.as_path();
    validate_namespace_chain(selected, false)?;
    let canonical_path =
        std::fs::canonicalize(selected).map_err(|source| inspect(selected, source))?;
    validate_namespace_chain(&canonical_path, true)?;

    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let executable = rustix::fs::openat(rustix::fs::CWD, &canonical_path, flags, Mode::empty())
        .map_err(|source| inspect(&canonical_path, io::Error::from(source)))?;
    let stat = rustix::fs::fstat(&executable)
        .map_err(|source| inspect(&canonical_path, io::Error::from(source)))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(unsafe_path(
            &canonical_path,
            "executable is not a regular file",
        ));
    }
    let euid = rustix::process::geteuid().as_raw();
    if stat.st_uid != euid && stat.st_uid != 0 {
        return Err(unsafe_path(
            &canonical_path,
            "executable is owned by a foreign UID",
        ));
    }
    let mode = raw_mode_u32(stat.st_mode);
    if mode & SHARED_WRITE_MASK != 0 {
        return Err(unsafe_path(
            &canonical_path,
            "executable is group- or world-writable",
        ));
    }
    if mode & EXECUTE_MASK == 0 {
        return Err(unsafe_path(
            &canonical_path,
            "file has no executable mode bit",
        ));
    }
    rustix::fs::accessat(
        rustix::fs::CWD,
        &canonical_path,
        rustix::fs::Access::EXEC_OK,
        rustix::fs::AtFlags::EACCESS,
    )
    .map_err(|_| {
        unsafe_path(
            &canonical_path,
            "effective user cannot execute selected file",
        )
    })?;
    reject_extended_acl(&executable, &canonical_path)?;
    reject_unpreserved_xattrs(&executable, &canonical_path)?;
    require_native_binary(&executable, &canonical_path)?;

    let selected_metadata =
        std::fs::metadata(selected).map_err(|source| inspect(selected, source))?;
    let identity = executable_identity(&stat, &canonical_path)?;
    if selected_metadata.dev() != identity.device || selected_metadata.ino() != identity.inode {
        return Err(UvExecutableProbeError::PathChanged);
    }
    Ok(OpenedExecutable {
        canonical_path,
        identity,
        executable,
    })
}

fn executable_identity(
    stat: &rustix::fs::Stat,
    path: &Path,
) -> Result<ExecutableIdentity, UvExecutableProbeError> {
    Ok(ExecutableIdentity {
        device: stat_device(stat.st_dev, path)?,
        inode: stat.st_ino,
        ctime_seconds: stat.st_ctime,
        ctime_nanoseconds: stat_ctime_nanoseconds(stat.st_ctime_nsec, path)?,
        size: u64::try_from(stat.st_size)
            .map_err(|_| unsafe_path(path, "executable size is negative"))?,
    })
}

/// Validate every lexical namespace used to resolve `path`. Calling this once
/// for the selected path and once for its canonical target covers both the
/// namespace containing each symlink and all directories reached by its target.
fn validate_namespace_chain(
    path: &Path,
    canonical_final: bool,
) -> Result<(), UvExecutableProbeError> {
    let euid = rustix::process::geteuid().as_raw();
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path(path, "executable has no parent directory"))?;
    let mut prefix = PathBuf::from("/");
    validate_directory(&prefix, euid)?;
    for component in parent.components().skip(1) {
        let name = match component {
            std::path::Component::Normal(name) => name,
            _ => return Err(unsafe_path(path, "path is not lexically normalized")),
        };
        prefix.push(name);
        let link_metadata =
            std::fs::symlink_metadata(&prefix).map_err(|source| inspect(&prefix, source))?;
        if link_metadata.file_type().is_symlink()
            && link_metadata.uid() != euid
            && link_metadata.uid() != 0
        {
            return Err(unsafe_path(
                &prefix,
                "ancestor symlink is owned by a foreign UID",
            ));
        }
        validate_directory(&prefix, euid)?;
    }
    if !canonical_final {
        let link_metadata =
            std::fs::symlink_metadata(path).map_err(|source| inspect(path, source))?;
        if link_metadata.file_type().is_symlink()
            && link_metadata.uid() != euid
            && link_metadata.uid() != 0
        {
            return Err(unsafe_path(
                path,
                "executable symlink is owned by a foreign UID",
            ));
        }
    }
    Ok(())
}

fn validate_directory(path: &Path, euid: u32) -> Result<(), UvExecutableProbeError> {
    let metadata = std::fs::metadata(path).map_err(|source| inspect(path, source))?;
    if !metadata.is_dir() {
        return Err(unsafe_path(path, "ancestor is not a directory"));
    }
    if degu_walk::directory_grants_foreign_mutation(metadata.uid(), metadata.mode(), euid) {
        return Err(unsafe_path(
            path,
            "ancestor namespace grants foreign mutation authority",
        ));
    }
    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(path, io::Error::from(source)))?;
    let opened =
        rustix::fs::fstat(&directory).map_err(|source| inspect(path, io::Error::from(source)))?;
    let device = stat_device(opened.st_dev, path)?;
    let inode = opened.st_ino;
    if device != metadata.dev() || inode != metadata.ino() {
        return Err(UvExecutableProbeError::PathChanged);
    }
    reject_extended_acl(&directory, path)
}

#[cfg(target_os = "linux")]
fn reject_extended_acl(fd: &impl AsFd, path: &Path) -> Result<(), UvExecutableProbeError> {
    let names = list_xattrs(fd).map_err(|source| UvExecutableProbeError::AclInspection {
        path: path.to_path_buf(),
        source,
    })?;
    if names
        .split(|byte| *byte == 0)
        .any(|name| name == b"system.posix_acl_access")
    {
        return Err(unsafe_path(path, "extended ACL is present"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn reject_extended_acl(fd: &impl AsFd, path: &Path) -> Result<(), UvExecutableProbeError> {
    match crate::uv::grants_mutation(fd) {
        Ok(false) => Ok(()),
        Ok(true) => Err(unsafe_path(
            path,
            "extended ACL grants mutation authority or has an unknown tag",
        )),
        Err(source) => Err(UvExecutableProbeError::AclInspection {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn reject_unpreserved_xattrs(fd: &impl AsFd, path: &Path) -> Result<(), UvExecutableProbeError> {
    let names = list_xattrs(fd).map_err(|source| UvExecutableProbeError::XattrInspection {
        path: path.to_path_buf(),
        source,
    })?;
    if names.is_empty() {
        Ok(())
    } else {
        Err(unsafe_path(
            path,
            "extended attributes would not be preserved by executable snapshotting",
        ))
    }
}

fn list_xattrs(fd: &impl AsFd) -> io::Result<Vec<u8>> {
    let raw_fd = fd.as_fd().as_raw_fd();
    let size = flistxattr(raw_fd, std::ptr::null_mut(), 0)?;
    if size > MAX_XATTR_LIST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended attribute name list exceeds the safety bound",
        ));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut names = vec![0_u8; size];
    let read = flistxattr(raw_fd, names.as_mut_ptr().cast(), names.len())?;
    if read > names.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended attribute name list grew beyond the allocated bound",
        ));
    }
    names.truncate(read);
    Ok(names)
}

fn flistxattr(fd: libc::c_int, buffer: *mut libc::c_char, size: usize) -> io::Result<usize> {
    loop {
        #[cfg(target_os = "linux")]
        // SAFETY: buffer is null with size zero or names a writable allocation
        // of exactly `size` bytes; the descriptor remains borrowed and live.
        let result = unsafe { libc::flistxattr(fd, buffer, size) };
        #[cfg(target_os = "macos")]
        // SAFETY: same contract as Linux; options zero requests ordinary names.
        let result = unsafe { libc::flistxattr(fd, buffer, size, 0) };
        if result >= 0 {
            return usize::try_from(result)
                .map_err(|_| io::Error::other("extended attribute list size overflow"));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn require_native_binary(fd: &impl AsFd, path: &Path) -> Result<(), UvExecutableProbeError> {
    let mut magic = [0_u8; 4];
    let mut read = 0_usize;
    while read < magic.len() {
        // SAFETY: the live descriptor is borrowed and the remaining slice is a
        // valid writable allocation. pread does not alter its file offset.
        let result = unsafe {
            libc::pread(
                fd.as_fd().as_raw_fd(),
                magic[read..].as_mut_ptr().cast(),
                magic.len() - read,
                read as libc::off_t,
            )
        };
        if result > 0 {
            read += usize::try_from(result).expect("positive read count fits usize");
            continue;
        }
        if result == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(UvExecutableProbeError::Inspect {
            path: path.to_path_buf(),
            source: error,
        });
    }
    const MAGICS: [[u8; 4]; 9] = [
        *b"\x7fELF",
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
        [0xca, 0xfe, 0xba, 0xbf],
        [0xbf, 0xba, 0xfe, 0xca],
    ];
    if read != magic.len() || !MAGICS.contains(&magic) {
        return Err(UvExecutableProbeError::NotNativeBinary(path.to_path_buf()));
    }
    Ok(())
}

fn inspect(path: &Path, source: io::Error) -> UvExecutableProbeError {
    UvExecutableProbeError::Inspect {
        path: path.to_path_buf(),
        source,
    }
}

fn unsafe_path(path: &Path, reason: &'static str) -> UvExecutableProbeError {
    UvExecutableProbeError::UnsafePath {
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(target_vendor = "apple")]
fn stat_device(device: libc::dev_t, path: &Path) -> Result<u64, UvExecutableProbeError> {
    u64::try_from(device).map_err(|_| unsafe_path(path, "device ID is out of range"))
}

#[cfg(not(target_vendor = "apple"))]
fn stat_device(device: libc::dev_t, _path: &Path) -> Result<u64, UvExecutableProbeError> {
    Ok(device)
}

#[cfg(target_vendor = "apple")]
fn stat_ctime_nanoseconds(
    nanoseconds: libc::c_long,
    _path: &Path,
) -> Result<i64, UvExecutableProbeError> {
    Ok(nanoseconds)
}

#[cfg(not(target_vendor = "apple"))]
fn stat_ctime_nanoseconds(nanoseconds: u64, path: &Path) -> Result<i64, UvExecutableProbeError> {
    i64::try_from(nanoseconds).map_err(|_| unsafe_path(path, "ctime is out of range"))
}

#[cfg(target_vendor = "apple")]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    u32::from(mode)
}

#[cfg(not(target_vendor = "apple"))]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    mode
}

#[cfg(test)]
mod tests;
