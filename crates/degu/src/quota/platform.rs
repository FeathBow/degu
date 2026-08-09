#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use super::model::QuotaSnapshot;
#[cfg(target_os = "linux")]
use super::model::{QuotaScope, QuotaScopeIdentity};
use crate::presentation::escape_terminal_text as escaped;
use std::fmt;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) struct MountInfo {
    pub(super) mount_point: PathBuf,
    pub(super) filesystem: String,
    #[cfg(target_os = "linux")]
    pub(super) source: PathBuf,
    #[cfg(target_os = "linux")]
    pub(super) mount_id: u64,
    #[cfg(target_os = "linux")]
    pub(super) device_major: u32,
    #[cfg(target_os = "linux")]
    pub(super) device_minor: u32,
}

#[cfg(target_os = "linux")]
impl MountInfo {
    pub(super) fn scope(self, path: &Path) -> QuotaScope {
        let identity = QuotaScopeIdentity::new(
            self.mount_id,
            self.device_major,
            self.device_minor,
            self.source,
        );
        QuotaScope::new(path.to_owned(), self.mount_point, self.filesystem, identity)
    }
}

#[derive(Debug)]
pub(crate) enum ProbeError {
    #[cfg(target_os = "linux")]
    NotConfigured {
        filesystem: String,
        mount_point: String,
    },
    Unsupported {
        filesystem: String,
        mount_point: String,
        reason: &'static str,
    },
    #[cfg(any(target_os = "linux", test))]
    Unavailable {
        filesystem: String,
        mount_point: String,
        reason: String,
    },
    #[cfg(target_os = "linux")]
    PermissionDenied {
        filesystem: String,
        mount_point: String,
        reason: String,
    },
    #[cfg(target_os = "linux")]
    Incomplete {
        filesystem: String,
        mount_point: String,
        reason: String,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Io {
        path: String,
        source: std::io::Error,
    },
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_os = "linux")]
            Self::NotConfigured {
                filesystem,
                mount_point,
            } => write!(
                formatter,
                "quota not configured for {} mounted at {}",
                escaped(filesystem),
                escaped(mount_point)
            ),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Io { path, source } => write!(
                formatter,
                "quota probe failed for {}: {}",
                escaped(path),
                escaped(&source.to_string())
            ),
            _ => write_failure(formatter, self),
        }
    }
}

impl ProbeError {
    pub(crate) fn category(&self) -> &'static str {
        match self {
            #[cfg(target_os = "linux")]
            Self::NotConfigured { .. } => "not_configured",
            Self::Unsupported { .. } => "unsupported",
            #[cfg(any(target_os = "linux", test))]
            Self::Unavailable { .. } => "unavailable",
            #[cfg(target_os = "linux")]
            Self::PermissionDenied { .. } => "permission_denied",
            #[cfg(target_os = "linux")]
            Self::Incomplete { .. } => "incomplete",
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Io { .. } => "io",
        }
    }

    /// Raw diagnostic for structured JSON. Terminal escaping belongs only to
    /// human presentation and must never be persisted in machine output.
    pub(crate) fn raw_message(&self) -> String {
        match self {
            #[cfg(target_os = "linux")]
            Self::NotConfigured {
                filesystem,
                mount_point,
            } => format!("quota not configured for {filesystem} mounted at {mount_point}"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Io { path, source } => {
                format!("quota probe failed for {path}: {source}")
            }
            _ => {
                let (label, filesystem, mount_point, reason) = failure_fields(self);
                format!("{label} for {filesystem} mounted at {mount_point}: {reason}")
            }
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn write_failure(formatter: &mut fmt::Formatter<'_>, error: &ProbeError) -> fmt::Result {
    let (label, filesystem, mount_point, reason) = failure_fields(error);
    write!(
        formatter,
        "{label} for {} mounted at {}: {}",
        escaped(filesystem),
        escaped(mount_point),
        escaped(reason)
    )
}

fn failure_fields(error: &ProbeError) -> (&'static str, &str, &str, &str) {
    match error {
        ProbeError::Unsupported {
            filesystem,
            mount_point,
            reason,
        } => (
            "quota unsupported",
            filesystem.as_str(),
            mount_point.as_str(),
            *reason,
        ),
        #[cfg(any(target_os = "linux", test))]
        ProbeError::Unavailable {
            filesystem,
            mount_point,
            reason,
        } => (
            "quota provider unavailable",
            filesystem.as_str(),
            mount_point.as_str(),
            reason.as_str(),
        ),
        #[cfg(target_os = "linux")]
        ProbeError::PermissionDenied {
            filesystem,
            mount_point,
            reason,
        } => (
            "quota permission denied",
            filesystem.as_str(),
            mount_point.as_str(),
            reason.as_str(),
        ),
        #[cfg(target_os = "linux")]
        ProbeError::Incomplete {
            filesystem,
            mount_point,
            reason,
        } => (
            "quota provider returned incomplete data",
            filesystem.as_str(),
            mount_point.as_str(),
            reason.as_str(),
        ),
        _ => unreachable!("non-failure variants are formatted directly"),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn probe(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    linux::probe(path)
}

#[cfg(target_os = "macos")]
pub(super) fn probe(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    macos::probe(path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn probe(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    Err(ProbeError::Unsupported {
        filesystem: "unknown".to_owned(),
        mount_point: path.display().to_string(),
        reason: "this platform has no validated authoritative quota provider",
    })
}

#[cfg(test)]
mod tests {
    use super::ProbeError;

    #[test]
    fn quota_probe_errors_escape_terminal_controls() {
        let error = ProbeError::Unavailable {
            filesystem: "ext4\x1b[31m".to_owned(),
            mount_point: "/mnt/bad\nmount".to_owned(),
            reason: "provider\tfailed\x07".to_owned(),
        };

        let rendered = error.to_string();

        assert!(!rendered.contains('\x1b'));
        assert!(rendered.contains("ext4\\u{1b}[31m"));
        assert!(rendered.contains("/mnt/bad\\nmount"));
        assert!(rendered.contains("provider\\tfailed\\u{7}"));
    }
}
