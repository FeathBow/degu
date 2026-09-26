use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use degu_core::config::AdvisoryConfig;

const FOREIGN_WRITE_BITS: u32 = 0o022;
const OWNER_EXECUTE_BIT: u32 = 0o100;

/// Where an advisor is found without any configuration.
///
/// Dropping an executable at `$XDG_CONFIG_HOME/degu/advisor` is the whole
/// setup. An account with no such file consults nobody and sends nothing, which
/// is what an untouched install has to do on a login node; an account that put
/// one there has already answered the question, and answered it knowing what it
/// was for. Asking during setup would take that answer before the reader has
/// ever met the kind of location it is about.
pub(crate) const CONVENTION_NAME: &str = "advisor";

/// How degu found the advisor it is about to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Named by `advisory.command`.
    Configured,
    /// Found at the conventional path, with nothing configured.
    Convention,
}

/// What degu will do about an advisor, decided before one runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    Found {
        path: PathBuf,
        origin: Origin,
    },
    /// Nothing named and nothing at the conventional path.
    Absent {
        convention: PathBuf,
    },
    /// Something is there that degu will not run, and why.
    ///
    /// Never silently skipped: a reader who put a file there meant it to be
    /// used, and one degu declines to exec is a thing they need told.
    Refused {
        path: PathBuf,
        reason: String,
    },
}

/// Decide which advisor to run, if any.
///
/// A configured path wins, because naming one is an explicit choice. The
/// conventional path is consulted only when nothing is named.
pub(crate) fn resolve_advisor(config: &AdvisoryConfig, config_home: &Path) -> Resolution {
    let convention = config_home.join("degu").join(CONVENTION_NAME);
    match config.command.as_deref() {
        Some(command) => admit(PathBuf::from(command), Origin::Configured, &convention),
        None => admit(convention.clone(), Origin::Convention, &convention),
    }
}

/// An advisor runs with this account's privileges, so the question is whether
/// anyone else decides what it does. A file another account can rewrite is one
/// degu would be executing on their behalf.
fn admit(path: PathBuf, origin: Origin, convention: &Path) -> Resolution {
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match origin {
                Origin::Configured => Resolution::Refused {
                    path,
                    reason: "nothing exists at this path".to_owned(),
                },
                Origin::Convention => Resolution::Absent {
                    convention: convention.to_path_buf(),
                },
            };
        }
        Err(error) => {
            return Resolution::Refused {
                path,
                reason: format!("it could not be inspected: {error}"),
            };
        }
    };
    let checked = validate_metadata(&metadata).and_then(|()| validate_acl(&path, &metadata));
    match checked {
        Ok(()) => Resolution::Found { path, origin },
        Err(reason) => Resolution::Refused { path, reason },
    }
}

fn validate_metadata(metadata: &std::fs::Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err("it is not a regular file".to_owned());
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err("it belongs to another account".to_owned());
    }
    if metadata.mode() & FOREIGN_WRITE_BITS != 0 {
        return Err("it is writable by its group or by everyone".to_owned());
    }
    if metadata.mode() & OWNER_EXECUTE_BIT == 0 {
        return Err("it is not executable".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_acl(path: &Path, expected: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("its ACL could not be inspected: {error}"))?;
    let actual = file
        .metadata()
        .map_err(|error| format!("it could not be inspected: {error}"))?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err("it changed while its permissions were inspected".to_owned());
    }
    validate_metadata(&actual)?;
    match crate::acl::grants_mutation(&file) {
        Ok(false) => Ok(()),
        Ok(true) => Err("its ACL grants mutation permissions".to_owned()),
        Err(error) => Err(format!("its ACL could not be inspected: {error}")),
    }
}

#[cfg(not(target_os = "macos"))]
fn validate_acl(_path: &Path, _expected: &std::fs::Metadata) -> Result<(), String> {
    // Linux POSIX access ACL grants are bounded by the group mode mask, which
    // validate_metadata already rejects whenever it includes write access.
    Ok(())
}
