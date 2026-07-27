//! Filesystem flavor detection for concurrency defaults.

use std::path::Path;

#[cfg(target_os = "linux")]
const LINUX_F_TYPE_MASK: u64 = u32::MAX as u64;
const PARALLEL_CONCURRENCY: usize = 4;
const CAUTIOUS_CONCURRENCY: usize = 2;
const SERIAL_CONCURRENCY: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "non-Linux builds retain the shared concurrency policy table"
    )
)]
pub enum FsFlavor {
    Local,
    Nfs,
    Smb,
    #[cfg(target_os = "macos")]
    WebDav,
    Fuse,
    Lustre,
    Gpfs,
    BeeGfs,
    CephFs,
    Tmpfs,
    Unknown,
}

#[cfg(target_os = "linux")]
const LINUX_MAGIC_FLAVORS: &[(u64, FsFlavor)] = &[
    (0x0BD0_0BD0, FsFlavor::Lustre),
    (0x4750_4653, FsFlavor::Gpfs),
    (0x1983_0326, FsFlavor::BeeGfs),
    (0x00C3_6400, FsFlavor::CephFs),
    (0x0000_6969, FsFlavor::Nfs),
    (0xFF53_4D42, FsFlavor::Smb),
    (0xFE53_4D42, FsFlavor::Smb),
    (0x6573_5546, FsFlavor::Fuse),
    (0x0102_1994, FsFlavor::Tmpfs),
    (0x0000_EF53, FsFlavor::Local),
    (0x5846_5342, FsFlavor::Local),
    (0x9123_683E, FsFlavor::Local),
    (0x2FC1_2FC1, FsFlavor::Local),
    (0x794C_7630, FsFlavor::Local),
];

impl FsFlavor {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Nfs => "nfs",
            Self::Smb => "smb",
            #[cfg(target_os = "macos")]
            Self::WebDav => "webdav",
            Self::Fuse => "fuse",
            Self::Lustre => "lustre",
            Self::Gpfs => "gpfs",
            Self::BeeGfs => "beegfs",
            Self::CephFs => "cephfs",
            Self::Tmpfs => "tmpfs",
            Self::Unknown => "unknown",
        }
    }
}

#[cfg(target_os = "linux")]
pub fn detect(root: &Path) -> FsFlavor {
    match rustix::fs::statfs(root) {
        Ok(stat) => {
            // Linux f_type has arch-dependent signedness/width. All magic
            // values here are 32-bit, so mask to the low 32 bits before comparing.
            let magic = stat.f_type as u64 & LINUX_F_TYPE_MASK;
            flavor_from_linux_magic(magic)
        }
        Err(_) => FsFlavor::Unknown,
    }
}

#[cfg(target_os = "macos")]
pub fn detect(root: &Path) -> FsFlavor {
    let Ok(stat) = rustix::fs::statfs(root) else {
        return FsFlavor::Unknown;
    };
    flavor_from_macos_name(stat.f_fstypename.iter().map(|byte| *byte as u8))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn detect(_root: &Path) -> FsFlavor {
    FsFlavor::Unknown
}

/// Keep metadata concurrency bounded according to filesystem behavior.
pub fn default_concurrency(flavor: FsFlavor) -> usize {
    match flavor {
        FsFlavor::Local | FsFlavor::Tmpfs | FsFlavor::Gpfs => PARALLEL_CONCURRENCY,
        FsFlavor::Nfs | FsFlavor::Smb | FsFlavor::Fuse | FsFlavor::Unknown => CAUTIOUS_CONCURRENCY,
        #[cfg(target_os = "macos")]
        FsFlavor::WebDav => CAUTIOUS_CONCURRENCY,
        FsFlavor::Lustre | FsFlavor::BeeGfs | FsFlavor::CephFs => SERIAL_CONCURRENCY,
    }
}

#[cfg(target_os = "linux")]
fn flavor_from_linux_magic(magic: u64) -> FsFlavor {
    LINUX_MAGIC_FLAVORS
        .iter()
        .find_map(|(candidate, flavor)| (*candidate == magic).then_some(*flavor))
        .unwrap_or(FsFlavor::Unknown)
}

#[cfg(target_os = "macos")]
fn flavor_from_macos_name(bytes: impl Iterator<Item = u8>) -> FsFlavor {
    let name = bytes.take_while(|byte| *byte != 0).collect::<Vec<_>>();
    match name.as_slice() {
        b"apfs" | b"hfs" => FsFlavor::Local,
        b"nfs" => FsFlavor::Nfs,
        b"smbfs" => FsFlavor::Smb,
        b"webdav" => FsFlavor::WebDav,
        b"tmpfs" => FsFlavor::Tmpfs,
        _ => FsFlavor::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_concurrency_matches_flavor_table() {
        assert_eq!(default_concurrency(FsFlavor::Local), 4);
        assert_eq!(default_concurrency(FsFlavor::Tmpfs), 4);
        assert_eq!(default_concurrency(FsFlavor::Nfs), 2);
        assert_eq!(default_concurrency(FsFlavor::Smb), 2);
        #[cfg(target_os = "macos")]
        assert_eq!(default_concurrency(FsFlavor::WebDav), 2);
        assert_eq!(default_concurrency(FsFlavor::Fuse), 2);
        assert_eq!(default_concurrency(FsFlavor::Unknown), 2);
        assert_eq!(default_concurrency(FsFlavor::Lustre), 1);
        assert_eq!(default_concurrency(FsFlavor::Gpfs), 4);
        assert_eq!(default_concurrency(FsFlavor::BeeGfs), 1);
        assert_eq!(default_concurrency(FsFlavor::CephFs), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unknown_magic_maps_to_unknown() {
        assert_eq!(flavor_from_linux_magic(0), FsFlavor::Unknown);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_detects_dev_shm_as_tmpfs() {
        assert_eq!(detect(Path::new("/dev/shm")), FsFlavor::Tmpfs);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tempdir_is_not_hpc_network_flavor() {
        let dir = tempfile::tempdir().unwrap();
        let flavor = detect(dir.path());

        assert!(!matches!(
            flavor,
            FsFlavor::Lustre | FsFlavor::Gpfs | FsFlavor::BeeGfs | FsFlavor::CephFs
        ));
        assert!(default_concurrency(flavor) >= 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_name_mapping_covers_supported_flavors() {
        let cases = [
            (&b"apfs"[..], FsFlavor::Local),
            (&b"hfs"[..], FsFlavor::Local),
            (&b"nfs"[..], FsFlavor::Nfs),
            (&b"smbfs"[..], FsFlavor::Smb),
            (&b"webdav"[..], FsFlavor::WebDav),
            (&b"tmpfs"[..], FsFlavor::Tmpfs),
            (&b"autofs"[..], FsFlavor::Unknown),
            (&b""[..], FsFlavor::Unknown),
        ];

        for (name, expected) in cases {
            assert_eq!(flavor_from_macos_name(name.iter().copied()), expected);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_detects_root_as_local() {
        assert_eq!(detect(Path::new("/")), FsFlavor::Local);
    }
}
