use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub(super) const CLAIMS_DIR_NAME: &str = ".claims";
const SHARED_WRITE_MASK: u32 = 0o022;

pub(crate) fn validate_existing_claims_dir(trash_root: &Path) -> io::Result<Option<PathBuf>> {
    let claims = trash_root.join(CLAIMS_DIR_NAME);
    let metadata = match std::fs::symlink_metadata(&claims) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "purge claims path is not a real directory: {}",
                claims.display()
            ),
        ));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "purge claims directory is not owned by the effective user: {}",
                claims.display()
            ),
        ));
    }
    if metadata.mode() & SHARED_WRITE_MASK != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "purge claims directory is group- or world-writable: {}",
                claims.display()
            ),
        ));
    }
    Ok(Some(claims))
}

pub(crate) fn interrupted_purge_claims(trash_root: &Path) -> io::Result<Vec<PathBuf>> {
    Ok(interrupted_purge_claims_until(trash_root, None)?.claims)
}

pub(crate) struct InterruptedClaims {
    pub(crate) claims: Vec<PathBuf>,
    pub(crate) truncated: bool,
}

/// Abandon the `.claims` walk once `deadline` passes so a large claims directory
/// cannot outrun a scan budget the caller has already spent; `truncated` then
/// reports the returned count is a lower bound rather than the full total.
pub(crate) fn interrupted_purge_claims_until(
    trash_root: &Path,
    deadline: Option<Instant>,
) -> io::Result<InterruptedClaims> {
    let Some(claims) = validate_existing_claims_dir(trash_root)? else {
        return Ok(InterruptedClaims {
            claims: Vec::new(),
            truncated: false,
        });
    };
    let mut interrupted = Vec::new();
    for entry in std::fs::read_dir(claims)? {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(InterruptedClaims {
                claims: interrupted,
                truncated: true,
            });
        }
        let entry = entry?;
        if reservation_marker_metadata(&entry)?.is_none() {
            interrupted.push(entry.path());
        }
    }
    interrupted.sort();
    Ok(InterruptedClaims {
        claims: interrupted,
        truncated: false,
    })
}

pub(crate) fn is_sequence_claim(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit)
}

pub(crate) fn reservation_marker_metadata(
    entry: &std::fs::DirEntry,
) -> io::Result<Option<std::fs::Metadata>> {
    if !is_sequence_claim(&entry.file_name()) {
        return Ok(None);
    }
    let metadata = std::fs::symlink_metadata(entry.path())?;
    let is_marker = metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() == 0;
    Ok(is_marker.then_some(metadata))
}
