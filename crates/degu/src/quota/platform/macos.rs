use super::{MountInfo, ProbeError};
use crate::quota::model::QuotaSnapshot;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub(super) fn probe(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    let mount = inspect_mount(path)?;
    Err(ProbeError::Unsupported {
        filesystem: mount.filesystem,
        mount_point: mount.mount_point.display().to_string(),
        reason: "authoritative user quota reporting is not validated on macOS; use `degu scan` to inspect storage detected by degu",
    })
}

fn inspect_mount(path: &Path) -> Result<MountInfo, ProbeError> {
    let path_string = c_path(path)?;
    let mut raw = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: statfs initializes `raw` on success and receives a NUL-terminated path.
    let result = unsafe { libc::statfs(path_string.as_ptr(), raw.as_mut_ptr()) };
    if result != 0 {
        return Err(io_error(path, std::io::Error::last_os_error()));
    }
    // SAFETY: a successful statfs call initialized the complete structure.
    let raw = unsafe { raw.assume_init() };
    Ok(MountInfo {
        mount_point: PathBuf::from(c_array(&raw.f_mntonname)),
        filesystem: c_array(&raw.f_fstypename),
    })
}

fn c_path(path: &Path) -> Result<CString, ProbeError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io_error(
            path,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte"),
        )
    })
}

fn c_array(value: &[libc::c_char]) -> String {
    let bytes = value
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn io_error(path: &Path, source: std::io::Error) -> ProbeError {
    ProbeError::Io {
        path: path.display().to_string(),
        source,
    }
}
