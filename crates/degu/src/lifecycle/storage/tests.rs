use super::{
    TRASHROOTS_FILE, ensure_managed_trash_root, ensure_managed_trash_root_with_sync,
    read_registered_trash_roots, register_trash_root, register_trash_root_with_sync, trash_roots,
};
use degu_core::ecosystem::DetectCtx;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn managed_trash_root_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let root = ensure_managed_trash_root(&dir.path().join("degu/trash"), "trash").unwrap();

    let mode = std::fs::symlink_metadata(&root).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let parent_mode = std::fs::symlink_metadata(root.parent().unwrap())
        .unwrap()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700);
}

#[test]
fn unsafe_cross_device_parent_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
    let root = dir.path().join(".degu-trash");

    let error = ensure_managed_trash_root(&root, ".degu-trash").unwrap_err();

    assert!(error.to_string().contains("without the sticky bit"));
}

#[test]
fn group_writable_trash_root_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("trash");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();

    let error = ensure_managed_trash_root(&root, "trash").unwrap_err();

    assert!(error.to_string().contains("group- or world-writable"));
}

#[test]
fn registration_refuses_a_corrupt_registry_line() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let registry = state.join(TRASHROOTS_FILE);
    std::fs::create_dir_all(registry.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        registry.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let original = b"\"/not-trash\"\n";
    std::fs::write(&registry, original).unwrap();
    let root = dir.path().join(".degu-trash");

    let error = register_trash_root(&state, &root).unwrap_err();

    assert!(
        error.to_string().contains("corrupt trash registry line 1"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(&registry).unwrap(), original);
}

#[test]
fn registration_seals_a_valid_unterminated_tail_before_appending() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let registry = state.join(TRASHROOTS_FILE);
    std::fs::create_dir_all(registry.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        registry.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(&registry, b"\"/old/.degu-trash\"").unwrap();
    let root = dir.path().join(".degu-trash");

    register_trash_root(&state, &root).unwrap();

    let encoded = serde_json::to_string(root.to_str().unwrap()).unwrap();
    let expected = format!("\"/old/.degu-trash\"\n{encoded}\n");
    assert_eq!(std::fs::read(&registry).unwrap(), expected.as_bytes());
    assert_eq!(
        read_registered_trash_roots(&registry).unwrap(),
        vec![std::path::PathBuf::from("/old/.degu-trash"), root]
    );
}

#[test]
fn lexical_aliases_of_one_trash_root_resolve_to_a_single_root() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();

    let base = home.path().join("cache");
    std::fs::create_dir_all(&base).unwrap();
    let sub = base.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    for path in [home.path(), base.as_path(), sub.as_path()] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let real = base.join(".degu-trash");
    ensure_managed_trash_root(&real, ".degu-trash").unwrap();

    let alias = base.join("sub/../.degu-trash");
    let state_dir = state.path().join("degu");
    register_trash_root(state.path(), &real).unwrap();
    register_trash_root(state.path(), &alias).unwrap();
    assert_eq!(
        read_registered_trash_roots(&state_dir.join("trashroots"))
            .unwrap()
            .len(),
        2
    );

    let ctx = DetectCtx::for_test(
        home.path().to_path_buf(),
        [(
            "XDG_STATE_HOME".to_owned(),
            state.path().as_os_str().to_owned(),
        )],
    );
    let roots = trash_roots(&ctx).unwrap();
    let cross_device = roots
        .iter()
        .filter(|root| root.file_name() == Some(std::ffi::OsStr::new(".degu-trash")))
        .count();
    assert_eq!(cross_device, 1, "aliases must fold to one root: {roots:?}");
}

#[test]
fn registration_frames_line_breaks_in_a_root() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let root = dir.path().join("line\nbreak/.degu-trash");

    register_trash_root(&state, &root).unwrap();

    assert_eq!(
        read_registered_trash_roots(&state.join(TRASHROOTS_FILE)).unwrap(),
        vec![root]
    );
}

#[test]
fn trash_root_parent_sync_failure_blocks_before_staging_admission() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = dir.path().join(".degu-trash");
    let mut calls = 0;
    let error = ensure_managed_trash_root_with_sync(&root, ".degu-trash", |_| {
        calls += 1;
        if calls == 2 {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("trash-root parent"));
    assert!(root.is_dir());
}

#[test]
fn registry_parent_sync_failure_retries_without_duplicate_record() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let root = dir.path().join(".degu-trash");
    let mut calls = 0;
    let error = register_trash_root_with_sync(&state, &root, |_| {
        calls += 1;
        if calls == 2 {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("registry parent"));

    register_trash_root(&state, &root).unwrap();
    assert_eq!(
        read_registered_trash_roots(&state.join(TRASHROOTS_FILE)).unwrap(),
        vec![root]
    );
}
