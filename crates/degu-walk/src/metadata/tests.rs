#![cfg(target_os = "linux")]

use super::*;

#[test]
fn statx_file_meta_matches_std_file_meta_for_each_file_kind() {
    let fixture = MetadataFixture::new();
    for path in fixture.paths() {
        let statx = lstat(path).unwrap().meta;
        let standard = lstat_std(path).unwrap();

        assert_eq!(statx, standard, "{}", path.display());
    }
}

struct MetadataFixture {
    _dir: tempfile::TempDir,
    regular: std::path::PathBuf,
    subdir: std::path::PathBuf,
    hardlink_original: std::path::PathBuf,
    hardlink_peer: std::path::PathBuf,
    symlink: std::path::PathBuf,
}

impl MetadataFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular.bin");
        let subdir = dir.path().join("subdir");
        let hardlink_original = dir.path().join("hardlink-original.bin");
        let hardlink_peer = dir.path().join("hardlink-peer.bin");
        let symlink = dir.path().join("symlink");
        std::fs::write(&regular, [1_u8; 123]).unwrap();
        std::fs::create_dir(&subdir).unwrap();
        std::fs::write(&hardlink_original, [2_u8; 4096]).unwrap();
        std::fs::hard_link(&hardlink_original, &hardlink_peer).unwrap();
        std::os::unix::fs::symlink(&regular, &symlink).unwrap();
        set_mtime_nsec(&regular, 100_000_001);
        set_mtime_nsec(&subdir, 200_000_002);
        set_mtime_nsec(&hardlink_original, 300_000_003);
        set_mtime_nsec(&hardlink_peer, 300_000_003);
        set_mtime_nsec(&symlink, 400_000_004);
        Self {
            _dir: dir,
            regular,
            subdir,
            hardlink_original,
            hardlink_peer,
            symlink,
        }
    }

    fn paths(&self) -> [&Path; 5] {
        [
            &self.regular,
            &self.subdir,
            &self.hardlink_original,
            &self.hardlink_peer,
            &self.symlink,
        ]
    }
}

#[test]
fn std_file_meta_matches_expected_fallback_fields() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original.bin");
    let linked = dir.path().join("linked.bin");

    std::fs::write(&original, [0_u8; 2048]).unwrap();
    std::fs::hard_link(&original, &linked).unwrap();
    let meta = lstat_std(&original).unwrap();

    assert!(!meta.is_dir);
    assert_eq!(meta.len, 2048);
    assert!(meta.bytes_allocated >= 2048);
    assert_eq!(meta.nlink, 2);
    assert!(meta.mtime.is_some());
    assert_eq!(meta.dev, lstat_std(dir.path()).unwrap().dev);
}

fn set_mtime_nsec(path: &Path, nsec: i64) {
    use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, UTIME_OMIT};

    rustix::fs::utimensat(
        CWD,
        path,
        &Timestamps {
            last_access: Timespec {
                tv_sec: 0,
                tv_nsec: UTIME_OMIT,
            },
            last_modification: Timespec {
                tv_sec: 1_700_000_000,
                tv_nsec: nsec,
            },
        },
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
}
