//! Single source of truth for the activation-anchor path layout.
//!
//! The anchor path used to be spelled twice — a flat root constant consumed by
//! the open path in `store_activation`, and an independent component list
//! (`BASE_COMPONENTS` + `PRODUCT_COMPONENTS`) walked by the create path in
//! `activation_anchor_provisioning`. Both now derive from the components here,
//! so the create-time walk and the open-time leaf can never drift.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The XDG state suffix a self-managed anchor lives under, relative to the
/// account home. It is a fixed convention, never read from `$XDG_STATE_HOME`,
/// so ambient environment drift cannot select a different anchor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SELF_STATE_COMPONENTS: &[&str] = &[".local", "state"];

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MIN_PASSWD_BUFFER_BYTES: usize = 1024;

/// Why a self-managed anchor root could not be derived from account facts.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfAnchorRootError {
    /// `getpwuid_r` failed with this errno.
    Lookup(i32),
    /// The account database has no entry for the effective UID.
    AccountMissing,
    /// The account home is empty or not absolute, so joining it would depend on
    /// the working directory.
    HomeNotAbsolute,
}

/// The operating-system prefix. Provisioning treats it as existing-only and
/// never creates or repairs it.
#[cfg(target_os = "linux")]
pub(crate) const OS_PREFIX_COMPONENTS: &[&str] = &["var", "lib"];
#[cfg(target_os = "macos")]
pub(crate) const OS_PREFIX_COMPONENTS: &[&str] = &["private", "var", "db"];

/// The degu-owned scaffold published beneath the OS prefix. `[0]` is the product
/// namespace, `[1]` the per-UID leaf's parent.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const PRODUCT_COMPONENTS: &[&str] = &["degu", "store-activation"];

/// Absolute root that holds one per-UID anchor leaf, built from the same
/// components the provisioning walk uses.
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

/// Absolute root that holds the invoking account's own anchor leaf, derived from
/// the account database home (never `$HOME`/`$XDG_STATE_HOME`) plus the fixed XDG
/// state suffix and the same product components the system layout uses.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn self_anchor_root() -> Result<PathBuf, SelfAnchorRootError> {
    let uid = rustix::process::geteuid().as_raw();
    let home = passwd_home_dir(uid)
        .map_err(SelfAnchorRootError::Lookup)?
        .ok_or(SelfAnchorRootError::AccountMissing)?;
    if !home.is_absolute() {
        return Err(SelfAnchorRootError::HomeNotAbsolute);
    }
    let mut path = home;
    for component in SELF_STATE_COMPONENTS {
        path.push(component);
    }
    for component in PRODUCT_COMPONENTS {
        path.push(component);
    }
    Ok(path)
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn system_root_matches_the_documented_platform_path() {
        let expected = if cfg!(target_os = "linux") {
            "/var/lib/degu/store-activation"
        } else {
            "/private/var/db/degu/store-activation"
        };
        assert_eq!(system_anchor_root().to_str(), Some(expected));
    }

    #[test]
    fn self_root_lives_under_the_account_state_home() {
        // The test account has a home; derivation must be absolute and carry the
        // XDG state suffix plus the shared product tail, never the system prefix.
        let root = self_anchor_root().expect("test account has a home directory");
        assert!(root.is_absolute());
        assert!(
            root.ends_with(Path::new(".local/state/degu/store-activation")),
            "self root {root:?} must end with the XDG state product tail"
        );
        assert!(!root.starts_with("/var/lib/degu"));
        assert!(!root.starts_with("/private/var/db/degu"));
    }

    #[test]
    fn self_and_system_share_the_product_tail_only() {
        let self_root = self_anchor_root().expect("test account has a home directory");
        let system_root = system_anchor_root();
        assert_ne!(self_root, system_root);
        for tail in PRODUCT_COMPONENTS {
            assert!(self_root.components().any(|c| c.as_os_str() == *tail));
            assert!(system_root.components().any(|c| c.as_os_str() == *tail));
        }
    }
}
