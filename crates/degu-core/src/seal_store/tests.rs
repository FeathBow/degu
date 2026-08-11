use super::*;
use crate::authority::TransactionState;
use crate::seal_wal::{RecoveryLockError, TransactionId};
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn transaction(byte: u8) -> TransactionId {
    TransactionId([byte; 16])
}

fn temp_path(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().canonicalize().unwrap()
}

fn store(temp: &tempfile::TempDir) -> SealWalStore {
    SealWalStore::open_or_create(&temp_path(temp).join("wal-store")).unwrap()
}

#[test]
fn creates_private_store_and_exact_wal_modes() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    let store = SealWalStore::open_or_create(&root).unwrap();
    let lease = store.try_lease().unwrap();

    let directory = std::fs::metadata(&root).unwrap();
    let wal = std::fs::metadata(root.join(WAL_FILE_NAME)).unwrap();
    assert_eq!(directory.permissions().mode() & 0o7777, 0o700);
    assert_eq!(wal.permissions().mode() & 0o7777, 0o600);
    assert!(wal.is_file());
    assert_eq!(wal.nlink(), 1);
    drop(lease);
}

#[test]
fn store_initialization_publishes_the_wal_before_any_lease() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    drop(SealWalStore::open_or_create(&root).unwrap());

    let wal = std::fs::metadata(root.join(WAL_FILE_NAME)).unwrap();
    assert!(wal.is_file());
    assert_eq!(wal.permissions().mode() & 0o7777, 0o600);
    assert_eq!(wal.len(), 0);
}

#[test]
fn existing_only_open_never_creates_a_missing_store() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");

    assert!(matches!(
        SealWalStore::open_existing(&root),
        Err(StoreError::MissingStore { path }) if path == root
    ));
    assert!(!root.exists());
}

#[test]
fn existing_store_without_wal_is_never_reinitialized() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(
        SealWalStore::open_or_create(&root),
        Err(StoreError::MissingWal { path }) if path == root.join(WAL_FILE_NAME)
    ));
    assert!(!root.join(WAL_FILE_NAME).exists());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol authority loss
fn deleted_wal_is_lost_authority_not_an_empty_store() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    drop(SealWalStore::open_or_create(&root).unwrap());
    rustix::fs::unlinkat(
        rustix::fs::CWD,
        root.join(WAL_FILE_NAME),
        rustix::fs::AtFlags::empty(),
    )
    .unwrap();

    assert!(matches!(
        SealWalStore::open_or_create(&root),
        Err(StoreError::MissingWal { .. })
    ));
}

#[test]
fn existing_directory_retries_uncertain_parent_durability() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    let first_syncs = std::cell::Cell::new(0);
    let first = SealWalStore::open_or_create_with_sync(&root, |_| {
        let call = first_syncs.get();
        first_syncs.set(call + 1);
        if call == 4 {
            Err(io::Error::other("injected parent sync failure"))
        } else {
            Ok(())
        }
    });
    assert!(matches!(first, Err(StoreError::Io { .. })));
    assert!(root.is_dir());

    let retry_syncs = std::cell::Cell::new(0);
    let store = SealWalStore::open_or_create_with_sync(&root, |_| {
        retry_syncs.set(retry_syncs.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(retry_syncs.get(), 3);
    drop(store.try_lease().unwrap());
}

#[test]
fn every_store_initialization_sync_failure_reopens_without_empty_wal_recreation() {
    let temp = crate::secure_test_tempdir().unwrap();
    for failed_sync in 0..5 {
        let root = temp_path(&temp).join(format!("wal-store-{failed_sync}"));
        let calls = std::cell::Cell::new(0);
        let first = SealWalStore::open_or_create_with_sync(&root, |_| {
            let call = calls.get();
            calls.set(call + 1);
            if call == failed_sync {
                Err(io::Error::other("injected initialization sync failure"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(first, Err(StoreError::Io { .. })));
        if failed_sync < 2 {
            assert!(!root.exists());
            assert!(unpublished_initializer_exists(&root));
        } else {
            assert!(root.join(WAL_FILE_NAME).is_file());
        }

        let retry = SealWalStore::open_or_create_with_sync(&root, |_| Ok(())).unwrap();
        drop(retry.try_lease().unwrap());
    }
}

#[test]
fn final_store_name_is_published_only_after_wal_and_directory_sync() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    let observations = std::cell::RefCell::new(Vec::new());
    let store = SealWalStore::open_or_create_with_sync(&root, |_| {
        observations.borrow_mut().push(root.exists());
        Ok(())
    })
    .unwrap();
    assert_eq!(&*observations.borrow(), &[false, false, true, true, true]);
    drop(store.try_lease().unwrap());
}

#[test]
fn abandoned_unpublished_initializers_never_become_missing_wal_authority() {
    let temp = crate::secure_test_tempdir().unwrap();
    let parent = temp_path(&temp);
    let root = parent.join("wal-store");
    let abandoned_empty = parent.join(".degu-seal-store-initializing-old-empty");
    let abandoned_partial = parent.join(".degu-seal-store-initializing-old-partial");
    std::fs::create_dir(&abandoned_empty).unwrap();
    std::fs::create_dir(&abandoned_partial).unwrap();
    std::fs::write(abandoned_partial.join(WAL_FILE_NAME), b"").unwrap();

    let store = SealWalStore::open_or_create(&root).unwrap();
    assert!(root.join(WAL_FILE_NAME).is_file());
    assert!(abandoned_empty.is_dir());
    assert!(abandoned_partial.is_dir());
    drop(store.try_lease().unwrap());
}

#[test]
fn safe_owned_and_root_ancestor_chain_is_accepted() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("owned").join("wal-store");
    std::fs::create_dir(temp_path(&temp).join("owned")).unwrap();
    std::fs::set_permissions(
        temp_path(&temp).join("owned"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    drop(SealWalStore::open_or_create(&root).unwrap());
}

#[test]
fn rejects_nonsticky_foreign_writable_parent() {
    let temp = crate::secure_test_tempdir().unwrap();
    let shared = temp_path(&temp).join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();

    assert!(matches!(
        SealWalStore::open_or_create(&shared.join("wal-store")),
        Err(StoreError::UnsafeDirectory {
            reason: "non-sticky parent grants non-owner write and search",
            ..
        })
    ));
    assert!(!shared.join("wal-store").exists());
}

#[test]
fn rejects_relative_and_parent_traversal_store_paths() {
    assert!(matches!(
        SealWalStore::open_or_create(Path::new("relative/store")),
        Err(StoreError::InvalidPath(_))
    ));
    assert!(matches!(
        SealWalStore::open_or_create(Path::new("/tmp/../tmp/store")),
        Err(StoreError::InvalidPath("parent traversal is not allowed"))
    ));
}

#[test]
fn rejects_symlink_in_ancestor_chain() {
    let temp = crate::secure_test_tempdir().unwrap();
    let real = temp_path(&temp).join("real-parent");
    let alias = temp_path(&temp).join("alias-parent");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &alias).unwrap();

    assert!(matches!(
        SealWalStore::open_or_create(&alias.join("wal-store")),
        Err(StoreError::UnsafeDirectory {
            reason: "ancestor is not a no-follow directory",
            ..
        })
    ));
}

#[test]
fn rejects_store_binding_replaced_after_open() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    let moved = temp_path(&temp).join("moved-store");
    let store = SealWalStore::open_or_create(&root).unwrap();
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::UnsafeDirectory {
            reason: "opened directory is not the exact store entry",
            ..
        })
    ));
    assert!(moved.join(WAL_FILE_NAME).is_file());
    assert!(!root.join(WAL_FILE_NAME).exists());
}

#[test]
fn rejects_store_mode_drift_before_lease() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    let store = SealWalStore::open_or_create(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::UnsafeDirectory {
            reason: "directory mode is not exactly 0700",
            ..
        })
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_store_acl_drift_before_lease() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    let store = SealWalStore::open_or_create(&root).unwrap();
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(&root)
        .status()
        .unwrap();
    assert!(status.success());

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::UnsafeDirectory {
            reason: "directory ACL is present or could not be verified absent",
            ..
        })
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_wal_acl_drift_after_lockable_creation() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    let store = SealWalStore::open_or_create(&root).unwrap();
    drop(store.try_lease().unwrap());
    let wal = root.join(WAL_FILE_NAME);
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(&wal)
        .status()
        .unwrap();
    assert!(status.success());

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::UnsafeWal {
            reason: "WAL ACL is present or could not be verified absent",
            ..
        })
    ));
}

#[test]
fn rejects_permissive_existing_directory() {
    let temp = crate::secure_test_tempdir().unwrap();
    let root = temp_path(&temp).join("wal-store");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(matches!(
        SealWalStore::open_or_create(&root),
        Err(StoreError::UnsafeDirectory {
            reason: "directory mode is not exactly 0700",
            ..
        })
    ));
}

#[test]
fn rejects_symlink_store_and_wal_without_following_them() {
    let temp = crate::secure_test_tempdir().unwrap();
    let real = temp_path(&temp).join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let linked_store = temp_path(&temp).join("linked-store");
    std::os::unix::fs::symlink(&real, &linked_store).unwrap();
    assert!(SealWalStore::open_or_create(&linked_store).is_err());

    let root = temp_path(&temp).join("wal-store");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let victim = temp_path(&temp).join("victim");
    std::fs::write(&victim, b"must remain unchanged").unwrap();
    std::os::unix::fs::symlink(&victim, root.join(WAL_FILE_NAME)).unwrap();

    assert!(SealWalStore::open_or_create(&root).is_err());
    assert_eq!(std::fs::read(victim).unwrap(), b"must remain unchanged");
}

#[test]
fn rejects_permissive_existing_wal() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store = store(&temp);
    drop(store.try_lease().unwrap());
    let wal = temp_path(&temp).join("wal-store").join(WAL_FILE_NAME);
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::UnsafeWal {
            reason: "WAL mode is not exactly 0600",
            ..
        })
    ));
}

#[test]
fn rejects_hardlinked_wal() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store = store(&temp);
    drop(store.try_lease().unwrap());
    let wal = temp_path(&temp).join("wal-store").join(WAL_FILE_NAME);
    std::fs::hard_link(&wal, temp_path(&temp).join("alias")).unwrap();

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::UnsafeWal {
            reason: "WAL link count is not exactly one",
            ..
        })
    ));
}

#[test]
fn directory_creation_lock_closes_the_pre_fsync_publication_window() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store = store(&temp);
    let directory = File::open(temp_path(&temp).join("wal-store")).unwrap();
    directory.try_lock().unwrap();

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::Lease(RecoveryLockError::Busy))
    ));
}

#[test]
fn lease_excludes_recovery_and_append_for_writer_lifetime() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store = store(&temp);
    let writer = store.try_lease().unwrap().into_new_wal().unwrap();

    assert!(matches!(
        store.try_lease(),
        Err(StoreError::Lease(RecoveryLockError::Busy))
    ));
    drop(writer);
    store.try_lease().unwrap();
}

#[test]
fn resume_requires_replay_from_the_same_session() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store = store(&temp);
    let error = match store.try_lease().unwrap().resume() {
        Ok(_) => panic!("resume without replay must fail"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        crate::seal_wal::AppendError::InvalidState(_)
    ));
    store.try_lease().unwrap();
}

#[test]
fn replay_repair_and_resume_are_bound_to_one_locked_descriptor() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_a = store(&temp);
    let root_b = temp_path(&temp).join("other-store");
    let store_b = SealWalStore::open_or_create(&root_b).unwrap();

    let mut writer = store_a.try_lease().unwrap().into_new_wal().unwrap();
    writer.begin(transaction(1)).unwrap();
    drop(writer);
    drop(store_b.try_lease().unwrap().into_new_wal().unwrap());

    // Add a physically partial final header to A. Recovery must repair A only;
    // there is no API that accepts a second file descriptor.
    let wal_a = temp_path(&temp).join("wal-store").join(WAL_FILE_NAME);
    let mut raw = OpenOptions::new().append(true).open(&wal_a).unwrap();
    raw.write_all(b"DS").unwrap();
    raw.sync_all().unwrap();
    drop(raw);

    let mut lease = store_a.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.tail_repair.unwrap().truncated_bytes, 2);
    let mut writer = lease.resume().unwrap();
    writer
        .transition(transaction(1), TransactionState::ParentSealIntent)
        .unwrap();

    assert!(matches!(
        store_a.try_lease(),
        Err(StoreError::Lease(RecoveryLockError::Busy))
    ));
    drop(writer);

    let mut lease = store_a.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(
        replay.transactions[&transaction(1)].state,
        TransactionState::ParentSealIntent
    );
    assert_eq!(
        std::fs::metadata(root_b.join(WAL_FILE_NAME)).unwrap().len(),
        0
    );
}
