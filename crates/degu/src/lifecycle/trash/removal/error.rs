use std::io;
use std::path::Path;

use degu_walk::mount::MountIdentity;

pub(super) fn require_same_mount(
    path: &Path,
    expected: &MountIdentity,
    actual: &MountIdentity,
) -> io::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(mount_boundary(path))
    }
}

fn mount_boundary(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "refusing permanent deletion across mount boundary at {}",
            path.display()
        ),
    )
}

pub(super) fn contextual_error(
    operation: &str,
    path: &Path,
    error: rustix::io::Errno,
) -> io::Error {
    let kind = io::Error::from(error).kind();
    io::Error::new(
        kind,
        format!("failed to {operation} {}: {error}", path.display()),
    )
}
