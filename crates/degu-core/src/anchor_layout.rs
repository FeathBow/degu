//! Single source of truth for the activation-anchor path layout.
//!
//! The anchor path used to be spelled twice — a flat root constant consumed by
//! the open path in `store_activation`, and an independent component list
//! (`BASE_COMPONENTS` + `PRODUCT_COMPONENTS`) walked by the create path in
//! `activation_anchor_provisioning`. Both now derive from the components here,
//! so the create-time walk and the open-time leaf can never drift.

use std::path::PathBuf;

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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn system_root_matches_the_documented_platform_path() {
        let expected = if cfg!(target_os = "linux") {
            "/var/lib/degu/store-activation"
        } else {
            "/private/var/db/degu/store-activation"
        };
        assert_eq!(system_anchor_root().to_str(), Some(expected));
    }
}
