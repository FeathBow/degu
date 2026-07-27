//! Bounded, non-blocking reads of untrusted files.
//!
//! Probes across the workspace open files whose names are attacker-influenced
//! (a scanned directory may hold a `CACHEDIR.TAG`, `CMakeCache.txt`, or a config
//! file that the invoking user does not control). Two failure modes matter:
//!
//! * A named pipe (FIFO) at a probed name makes a plain `File::open` block
//!   forever when no writer is present; a `--budget` deadline cannot interrupt a
//!   syscall that is already parked in the kernel.
//! * A newline-free or enormous file slurped in one allocation is an
//!   out-of-memory vector on memory-tight nodes.

use rustix::fs::{FileType, Mode, OFlags};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Bytes read from a regular file, plus whether the byte cap cut the read short.
#[derive(Debug)]
pub struct CappedBytes {
    /// The file contents, at most the requested cap in length.
    pub bytes: Vec<u8>,
    /// `true` when the file was larger than the cap and the tail was dropped.
    pub truncated: bool,
}

/// Opens `path` read-only if and only if it resolves to a regular file.
///
/// Returns `Ok(None)` when the opened descriptor is a FIFO, device,
/// directory, or symlink target that is not a regular file — these are never
/// read, so a writer-less FIFO cannot hang the caller. Missing paths surface as
/// the usual [`io::ErrorKind::NotFound`] error so callers keep their existing
/// not-found handling.
///
/// The `O_NONBLOCK` used for the open is cleared before returning, so the
/// handle reads with normal blocking semantics.
pub fn open_regular_capped(path: &Path) -> io::Result<Option<File>> {
    // No NOFOLLOW: legitimately symlinked config files must still resolve.
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, flags, Mode::empty())?;

    // fstat the held descriptor, not the path, closing the open-then-check swap window.
    let stat = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Ok(None);
    }

    let file = File::from(fd);
    clear_nonblock(&file)?;
    Ok(Some(file))
}

/// Reads at most `cap` bytes from `path` when it is a regular file.
///
/// Returns `Ok(None)` for non-regular files (see [`open_regular_capped`]). The
/// read stops after `cap` bytes; [`CappedBytes::truncated`] reports whether more
/// data followed, so a caller can treat an over-cap file as indeterminate rather
/// than silently trusting a partial read.
pub fn read_regular_capped(path: &Path, cap: usize) -> io::Result<Option<CappedBytes>> {
    let Some(file) = open_regular_capped(path)? else {
        return Ok(None);
    };

    // Read one byte past the cap so a file that exactly fills the cap is not
    // misreported as truncated; the extra byte is dropped below.
    let probe_len = cap.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(probe_len as u64).read_to_end(&mut bytes)?;

    let truncated = bytes.len() > cap;
    bytes.truncate(cap);
    Ok(Some(CappedBytes { bytes, truncated }))
}

fn clear_nonblock(file: &File) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(file).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(file, flags - OFlags::NONBLOCK).map_err(io::Error::from)?;
    Ok(())
}

#[cfg(test)]
mod tests;
