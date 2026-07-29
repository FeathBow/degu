use std::io;
use std::path::Path;

use degu_core::oplog::{ObjectIdentity, ObjectKind};
use rustix::fs::{FileType, Stat};

#[derive(Clone, Copy)]
pub(in crate::lifecycle) enum IdentityExpectation {
    Exact(ObjectIdentity),
    Stable(ObjectIdentity),
}

impl IdentityExpectation {
    pub(in crate::lifecycle) fn require(
        self,
        path: &Path,
        actual: ObjectIdentity,
    ) -> io::Result<()> {
        let matches = match self {
            Self::Exact(expected) => expected == actual,
            Self::Stable(expected) => expected.same_object(&actual),
        };
        if matches {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("entry identity changed before deletion: {}", path.display()),
            ))
        }
    }
}

pub(in crate::lifecycle) fn object_identity_from_stat(stat: &Stat) -> ObjectIdentity {
    ObjectIdentity {
        kind: kind_from_mode(stat.st_mode),
        device: stat.st_dev as _,
        inode: stat.st_ino as _,
        ctime_seconds: stat.st_ctime as _,
        ctime_nanoseconds: stat.st_ctime_nsec as _,
    }
}

pub(super) fn kind_from_mode(mode: rustix::fs::RawMode) -> ObjectKind {
    match FileType::from_raw_mode(mode) {
        FileType::Directory => ObjectKind::Directory,
        FileType::RegularFile => ObjectKind::File,
        FileType::Symlink => ObjectKind::Symlink,
        _ => ObjectKind::Other,
    }
}
