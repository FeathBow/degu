//! Fixed activation-anchor layouts and account-base lookup.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The XDG state suffix a self-managed anchor lives under, relative to the
/// account home. It is a fixed convention, never read from `$XDG_STATE_HOME`,
/// so ambient environment drift cannot select a different anchor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const SELF_STATE_COMPONENTS: &[&str] = &[".local", "state"];

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MIN_PASSWD_BUFFER_BYTES: usize = 1024;

/// Errors resolving the current effective user's account base.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccountBaseError {
    /// `getpwuid_r` failed with this errno.
    #[error("account lookup failed with errno {0}")]
    Lookup(i32),
    /// The account database has no entry for the effective UID.
    #[error("the effective UID has no account database entry")]
    AccountMissing,
    /// The account home is empty or not absolute, so joining it would depend on
    /// the working directory.
    #[error("the account home is empty or not absolute")]
    HomeNotAbsolute,
}

/// The operating-system prefix. Provisioning treats it as existing-only and
/// never creates or repairs it.
#[cfg(target_os = "linux")]
pub(super) const OS_PREFIX_COMPONENTS: &[&str] = &["var", "lib"];
#[cfg(target_os = "macos")]
pub(super) const OS_PREFIX_COMPONENTS: &[&str] = &["private", "var", "db"];

/// The degu-owned scaffold published beneath the OS prefix. `[0]` is the product
/// namespace, `[1]` the per-UID leaf's parent.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const PRODUCT_COMPONENTS: &[&str] = &["degu", "store-activation"];

/// Absolute parent of the per-UID system activation anchors.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn system_anchor_root() -> PathBuf {
    let mut path = PathBuf::from("/");
    for component in OS_PREFIX_COMPONENTS {
        path.push(component);
    }
    for component in PRODUCT_COMPONENTS {
        path.push(component);
    }
    path
}

/// Existing account-owned base beneath which the self-managed scaffold is
/// created. This is an account fact, never an environment-selected path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn self_anchor_base() -> Result<PathBuf, AccountBaseError> {
    let uid = rustix::process::geteuid().as_raw();
    let home = passwd_home_dir(uid)
        .map_err(AccountBaseError::Lookup)?
        .ok_or(AccountBaseError::AccountMissing)?;
    if !home.is_absolute() {
        return Err(AccountBaseError::HomeNotAbsolute);
    }
    Ok(home)
}

/// Home directory of `uid` from the account database. Uses `getpwuid_r`, not
/// `$HOME`, so the result is a stable account fact rather than ambient state.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn passwd_home_dir(uid: libc::uid_t) -> Result<Option<PathBuf>, i32> {
    // SAFETY: querying the recommended reentrant passwd buffer size takes no pointers.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer = vec![
        0_u8;
        usize::try_from(suggested)
            .unwrap_or(MIN_PASSWD_BUFFER_BYTES)
            .max(MIN_PASSWD_BUFFER_BYTES)
    ];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: entry, result, and buffer stay valid for the call; getpwuid_r
        // initializes entry on success.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            let capacity = buffer.len().checked_mul(2).ok_or(libc::ENOMEM)?;
            buffer.resize(capacity, 0);
            continue;
        }
        if status != 0 {
            return Err(status);
        }
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: successful getpwuid_r initialized entry.
        let entry = unsafe { entry.assume_init() };
        if entry.pw_dir.is_null() {
            return Err(libc::EINVAL);
        }
        // SAFETY: pw_dir points into the still-alive buffer and is a C string.
        let dir = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
        let bytes = dir.to_bytes();
        if bytes.is_empty() {
            return Ok(Some(PathBuf::new()));
        }
        return Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes))));
    }
}
