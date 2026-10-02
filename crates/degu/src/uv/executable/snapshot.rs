use super::attributes::{reject_extended_acl, reject_unpreserved_xattrs};
use super::error::{UvExecutableProbeError, inspect, unsafe_path};
use super::source::{OpenedExecutable, raw_mode_u32, validate_namespace_chain};
use crate::native::{HeldNativeExecutable, SNAPSHOT_FILE_NAME, cleanup_executable_snapshot};
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{fmt, io};

const MAX_EXECUTABLE_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;
const SNAPSHOT_DIRECTORY_ATTEMPTS: usize = 16;
const SNAPSHOT_SUFFIX_BYTES: usize = 16;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(super) fn validate_snapshot_parent_chain(temp: &Path) -> Result<(), UvExecutableProbeError> {
    if !temp.is_absolute() {
        return Err(unsafe_path(temp, "temporary directory is not absolute"));
    }
    validate_namespace_chain(&temp.join("degu-snapshot-placeholder"), true)?;
    let canonical = std::fs::canonicalize(temp).map_err(|source| inspect(temp, source))?;
    validate_namespace_chain(&canonical.join("degu-snapshot-placeholder"), true)
}

pub(super) fn snapshot_executable(
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
    let execution_path = guard.path.join(SNAPSHOT_FILE_NAME);
    let writer = rustix::fs::openat(
        guard.directory(),
        SNAPSHOT_FILE_NAME,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    copy_exact_bytes(source, &writer, &execution_path)?;
    rustix::fs::fchmod(&writer, Mode::from_raw_mode(0o500))
        .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    rustix::fs::fsync(&writer)
        .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    drop(writer);

    let executable = rustix::fs::openat(
        guard.directory(),
        SNAPSHOT_FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(&execution_path, io::Error::from(source)))?;
    verify_snapshot(&executable, &execution_path, source.identity.size)?;
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
    for _ in 0..SNAPSHOT_DIRECTORY_ATTEMPTS {
        let mut random = [0_u8; SNAPSHOT_SUFFIX_BYTES];
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
                let directory = open_snapshot_directory(&parent, &directory_name, &path)?;
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
    source: &OpenedExecutable,
    destination: &OwnedFd,
    path: &Path,
) -> Result<(), UvExecutableProbeError> {
    let expected = source.identity.size;
    let mut offset = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while offset < expected {
        let remaining = usize::try_from(
            (expected - offset).min(u64::try_from(buffer.len()).expect("buffer length fits u64")),
        )
        .expect("bounded chunk length fits usize");
        let read = pread(&source.executable, &mut buffer[..remaining], offset)
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
    if pread(&source.executable, &mut trailing, expected).map_err(|source| inspect(path, source))?
        != 0
    {
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

fn write_all(fd: &OwnedFd, buffer: &[u8]) -> io::Result<()> {
    let mut bytes = buffer;
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

fn verify_snapshot(
    executable: &OwnedFd,
    path: &Path,
    expected_size: u64,
) -> Result<(), UvExecutableProbeError> {
    let stat =
        rustix::fs::fstat(executable).map_err(|source| inspect(path, io::Error::from(source)))?;
    reject_extended_acl(executable, path)?;
    reject_unpreserved_xattrs(executable, path)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || raw_mode_u32(stat.st_mode) & 0o777 != 0o500
        || u64::try_from(stat.st_size).ok() != Some(expected_size)
    {
        return Err(unsafe_path(
            path,
            "private executable snapshot failed mode, kind, or size verification",
        ));
    }
    Ok(())
}

fn open_snapshot_directory(
    parent: &OwnedFd,
    directory_name: &OsString,
    path: &Path,
) -> Result<OwnedFd, UvExecutableProbeError> {
    let directory = rustix::fs::openat(
        parent,
        directory_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(path, io::Error::from(source)))?;
    rustix::fs::fchmod(&directory, Mode::from_raw_mode(0o700))
        .map_err(|source| inspect(path, io::Error::from(source)))?;
    reject_extended_acl(&directory, path)?;
    reject_unpreserved_xattrs(&directory, path)?;
    Ok(directory)
}
