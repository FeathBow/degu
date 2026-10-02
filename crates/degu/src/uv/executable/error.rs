use super::version::{UvVersion, UvVersionParseError};
use crate::native::{NativePreparationError, NativeRunnerError};
use std::io;
use std::path::{Path, PathBuf};

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
    #[error(
        "extended attribute {name} at {path} would not be preserved by executable snapshotting"
    )]
    UnpreservedXattr { path: PathBuf, name: String },
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

pub(super) fn inspect(path: &Path, source: io::Error) -> UvExecutableProbeError {
    UvExecutableProbeError::Inspect {
        path: path.to_path_buf(),
        source,
    }
}

pub(super) fn unsafe_path(path: &Path, reason: &'static str) -> UvExecutableProbeError {
    UvExecutableProbeError::UnsafePath {
        path: path.to_path_buf(),
        reason,
    }
}
