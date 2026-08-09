// Adversarial fixtures deliberately replace already-sealed entries to prove
// revalidation fails. Production mutation remains behind the verified engine.
#![allow(clippy::disallowed_methods)]

use super::*;
use std::ffi::OsString;
use std::fs::Permissions;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

// The workspace CI runs under umask 002, where `tempfile` and `create_dir`
// would leave fixture directories group-writable and the seal would reject them
// as shared-writable. Pin every fixture directory to 0o700 so the guard sees a
// private tree regardless of umask; tests that need a shared-writable path set
// it explicitly afterwards.
fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    let dir = tempfile::Builder::new().tempdir()?;
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn create_private_dir(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    std::fs::DirBuilder::new().create(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(0o700))
}

fn create_private_dir_all(path: impl AsRef<Path>) -> std::io::Result<()> {
    let mut cur = PathBuf::new();
    for component in path.as_ref().components() {
        cur.push(component);
        match std::fs::DirBuilder::new().create(&cur) {
            Ok(()) => std::fs::set_permissions(&cur, Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_private_file(path: impl AsRef<Path>, contents: &[u8]) {
    let path = path.as_ref();
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
}

fn selection(path: impl Into<PathBuf>) -> UvCacheRootSelection {
    UvCacheRootSelection::explicit(path.into()).unwrap()
}

fn seal(path: impl Into<PathBuf>) -> Result<SealedUvCacheRoot, UvCacheRootSealError> {
    let path = path.into();
    let tag = path.join("CACHEDIR.TAG");
    if !tag.exists() {
        write_private_file(&tag, b"Signature: 8a477f597d28d172789f06886806bc55\n");
    }
    if std::fs::symlink_metadata(path.join("sdists-v9")).is_err() {
        create_private_dir(path.join("sdists-v9")).unwrap();
    }
    seal_uv_cache_root_for_version(selection(path), AUDITED_UV_PRUNE_VERSION)
}

#[test]
fn selection_is_absolute_normalized_non_root_and_bounded() {
    assert!(matches!(
        UvCacheRootSelection::explicit(PathBuf::from("relative/cache")),
        Err(UvCacheRootSealError::SelectionNotAbsolute)
    ));
    assert!(matches!(
        UvCacheRootSelection::explicit(PathBuf::from("/")),
        Err(UvCacheRootSealError::SelectionNotNormalized)
    ));
    assert!(matches!(
        UvCacheRootSelection::explicit(PathBuf::from("/cache/../other")),
        Err(UvCacheRootSealError::SelectionNotNormalized)
    ));
    assert!(matches!(
        UvCacheRootSelection::explicit(PathBuf::from(OsString::from_vec(
            b"/cache\0other".to_vec()
        ))),
        Err(UvCacheRootSealError::SelectionNotNormalized)
    ));
    assert!(matches!(
        UvCacheRootSelection::explicit(PathBuf::from(format!(
            "/{}",
            "x".repeat(MAX_ROOT_PATH_BYTES)
        ))),
        Err(UvCacheRootSealError::SelectionTooLarge)
    ));
}

#[test]
fn only_the_exact_audited_prune_layout_can_mint_root_authority() {
    let temp = private_tempdir().unwrap();
    let result = seal_uv_cache_root_for_version(selection(temp.path()), UvVersion::new(0, 12, 2));
    assert!(matches!(
        result,
        Err(UvCacheRootSealError::UnsupportedVersion { .. })
    ));
    let sealed = seal(temp.path()).unwrap();
    assert!(sealed.require_version(AUDITED_UV_PRUNE_VERSION).is_ok());
    assert!(matches!(
        sealed.require_version(UvVersion::new(0, 12, 4)),
        Err(UvCacheRootSealError::ExecutableVersionMismatch)
    ));
}

#[test]
fn discovery_is_only_a_unique_uv_consistency_constraint() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("uv-root");
    create_private_dir(&root).unwrap();
    let ctx = DetectCtx::for_test(
        temp.path().to_path_buf(),
        [(
            OsString::from("UV_CACHE_DIR"),
            root.as_os_str().to_os_string(),
        )],
    );
    let registrations = degu_adapters::all();
    let uv = registrations
        .iter()
        .find(|adapter| adapter.id() == "uv")
        .unwrap();
    assert_eq!(require_unique_discovered_root(uv, &ctx).unwrap(), root);

    let other = registrations
        .iter()
        .find(|adapter| adapter.id() != "uv")
        .unwrap();
    assert!(matches!(
        require_unique_discovered_root(other, &ctx),
        Err(UvCacheRootSealError::NonUvAdapter(_))
    ));

    let missing_ctx = DetectCtx::for_test(
        temp.path().to_path_buf(),
        [(
            OsString::from("UV_CACHE_DIR"),
            OsString::from("/missing/degu-uv"),
        )],
    );
    assert!(matches!(
        require_unique_discovered_root(uv, &missing_ctx),
        Err(UvCacheRootSealError::AmbiguousDiscovery(0))
    ));
}

#[test]
fn explicit_selection_must_name_the_discovered_object() {
    let temp = private_tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    create_private_dir(&first).unwrap();
    create_private_dir(&second).unwrap();
    let sealed = seal(&first).unwrap();

    assert!(require_selection_matches_discovery(&first, &sealed).is_ok());
    assert!(matches!(
        require_selection_matches_discovery(&second, &sealed),
        Err(UvCacheRootSealError::SelectionMismatch)
    ));
}

#[test]
fn cache_root_must_not_equal_or_contain_home() {
    let temp = private_tempdir().unwrap();
    let home = temp.path().join("home");
    let inside_home_cache = home.join(".cache/uv");
    create_private_dir_all(&inside_home_cache).unwrap();
    let parent_seal = seal(temp.path()).unwrap();
    let home_seal = seal(&home).unwrap();
    let cache_seal = seal(&inside_home_cache).unwrap();
    let ctx = DetectCtx::for_test(home.clone(), [] as [(OsString, OsString); 0]);

    assert!(matches!(
        reject_selected_root_containing_home(&ctx, parent_seal.selection()),
        Err(UvCacheRootSealError::ContainsHome)
    ));
    assert!(matches!(
        reject_root_containing_home(&ctx, &parent_seal),
        Err(UvCacheRootSealError::ContainsHome)
    ));
    assert!(matches!(
        reject_root_containing_home(&ctx, &home_seal),
        Err(UvCacheRootSealError::ContainsHome)
    ));
    assert!(reject_root_containing_home(&ctx, &cache_seal).is_ok());
    let canonical_home = std::fs::canonicalize(&home).unwrap();
    assert!(
        identity_matches_home_or_ancestor(home_seal.identity, &canonical_home).unwrap(),
        "object identity catches aliases even without relying on path prefix"
    );
    assert!(!identity_matches_home_or_ancestor(cache_seal.identity, &canonical_home).unwrap());
}

#[test]
fn root_requires_a_private_real_cachedir_tag() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    create_private_dir(&root).unwrap();
    create_private_dir(root.join("sdists-v9")).unwrap();
    assert!(matches!(
        seal_uv_cache_root_for_version(selection(&root), AUDITED_UV_PRUNE_VERSION),
        Err(UvCacheRootSealError::Inspect { .. })
    ));

    write_private_file(root.join("CACHEDIR.TAG"), b"not a cache tag\n");
    assert!(matches!(
        seal_uv_cache_root_for_version(selection(&root), AUDITED_UV_PRUNE_VERSION),
        Err(UvCacheRootSealError::UnsafePath { reason, .. })
            if reason == "CACHEDIR.TAG does not carry the cache-directory signature"
    ));

    write_private_file(
        root.join("CACHEDIR.TAG"),
        b"Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    assert!(seal_uv_cache_root_for_version(selection(&root), AUDITED_UV_PRUNE_VERSION).is_ok());

    let no_scaffold = temp.path().join("no-scaffold");
    create_private_dir(&no_scaffold).unwrap();
    write_private_file(
        no_scaffold.join("CACHEDIR.TAG"),
        b"Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    assert!(matches!(
        seal_uv_cache_root_for_version(selection(&no_scaffold), AUDITED_UV_PRUNE_VERSION),
        Err(UvCacheRootSealError::MissingUvScaffold)
    ));
}

#[test]
fn cachedir_tag_content_and_attachment_are_revalidated() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    create_private_dir(&root).unwrap();
    let sealed = seal(&root).unwrap();
    std::fs::write(root.join("CACHEDIR.TAG"), b"changed\n").unwrap();
    assert!(sealed.revalidate().is_err());

    let second = temp.path().join("second");
    create_private_dir(&second).unwrap();
    create_private_dir(second.join("sdists-v9")).unwrap();
    let outside = temp.path().join("outside-tag");
    std::fs::write(&outside, b"Signature: 8a477f597d28d172789f06886806bc55\n").unwrap();
    std::os::unix::fs::symlink(&outside, second.join("CACHEDIR.TAG")).unwrap();
    assert!(matches!(
        seal_uv_cache_root_for_version(selection(&second), AUDITED_UV_PRUNE_VERSION),
        Err(UvCacheRootSealError::UnsafePath { reason, .. })
            if reason == "CACHEDIR.TAG is not a private, singly linked regular file"
    ));
}

#[test]
fn trusted_root_symlink_binds_to_one_canonical_directory() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    let selected = temp.path().join("selected");
    create_private_dir(&root).unwrap();
    std::os::unix::fs::symlink(&root, &selected).unwrap();

    let sealed = seal(&selected).unwrap();
    assert_eq!(sealed.selection().as_path(), selected);
    assert_eq!(
        sealed.canonical_path(),
        std::fs::canonicalize(root).unwrap()
    );
    sealed.revalidate().unwrap();
}

#[test]
fn root_requires_private_effective_user_mutation_authority() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    create_private_dir(&root).unwrap();
    std::fs::set_permissions(&root, Permissions::from_mode(0o770)).unwrap();

    assert!(matches!(
        seal(&root),
        Err(UvCacheRootSealError::UnsafePath { reason, .. })
            if reason == "directory is group- or world-writable"
    ));
}

#[test]
fn every_current_bucket_refuses_symlinks_and_non_directories() {
    for name in KNOWN_BUCKETS {
        let temp = private_tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        create_private_dir(&root).unwrap();
        create_private_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(name)).unwrap();
        assert!(matches!(
            seal(&root),
            Err(UvCacheRootSealError::UnsafePath { reason, .. })
                if reason == "known uv bucket is a symlink or non-directory"
        ));

        rustix::fs::unlinkat(
            rustix::fs::CWD,
            root.join(name),
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
        std::fs::write(root.join(name), b"not a bucket").unwrap();
        assert!(matches!(
            seal(&root),
            Err(UvCacheRootSealError::UnsafePath { reason, .. })
                if reason == "known uv bucket is a symlink or non-directory"
        ));
    }
}

#[test]
fn traversed_bucket_and_stale_directory_trees_exclude_shared_writers() {
    for top_level in [
        "sdists-v9",
        "wheels-v6",
        "archive-v0",
        "environments-v2",
        "wheels-v0",
    ] {
        let temp = private_tempdir().unwrap();
        let root = temp.path().join("root");
        let unsafe_child = root.join(top_level).join("unsafe");
        create_private_dir_all(&unsafe_child).unwrap();
        std::fs::set_permissions(&unsafe_child, Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            seal(&root),
            Err(UvCacheRootSealError::UnsafePath { reason, .. })
                if reason == "directory is group- or world-writable"
        ));
    }
}

#[test]
fn non_traversed_current_bucket_contents_are_outside_ordinary_prune_scope() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    let child = root.join("git-v0").join("shared-but-unvisited");
    create_private_dir_all(&child).unwrap();
    std::fs::set_permissions(&child, Permissions::from_mode(0o777)).unwrap();

    let sealed = seal(&root).unwrap();
    sealed.revalidate().unwrap();
}

#[test]
fn stale_symlink_is_not_followed_outside_the_selected_root() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    let outside = temp.path().join("outside");
    create_private_dir(&root).unwrap();
    create_private_dir(&outside).unwrap();
    let unsafe_outside = outside.join("unsafe");
    create_private_dir(&unsafe_outside).unwrap();
    std::fs::set_permissions(&unsafe_outside, Permissions::from_mode(0o777)).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("stale-v0")).unwrap();

    let sealed = seal(&root).unwrap();
    sealed.revalidate().unwrap();
}

#[test]
fn bucket_attachment_is_frozen_until_spawn_revalidation() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    let bucket = root.join("archive-v0");
    create_private_dir_all(&bucket).unwrap();
    let sealed = seal(&root).unwrap();

    rustix::fs::unlinkat(rustix::fs::CWD, &bucket, rustix::fs::AtFlags::REMOVEDIR).unwrap();
    create_private_dir(&bucket).unwrap();
    assert!(matches!(
        sealed.revalidate(),
        Err(UvCacheRootSealError::BucketChanged { name: "archive-v0" })
    ));
}

#[test]
fn bucket_permissions_are_rechecked_before_spawn() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    let bucket = root.join("archive-v0");
    create_private_dir_all(&bucket).unwrap();
    let sealed = seal(&root).unwrap();

    std::fs::set_permissions(&bucket, Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        sealed.revalidate(),
        Err(UvCacheRootSealError::BucketChanged { name: "archive-v0" })
    ));
}

#[test]
fn a_bucket_cannot_appear_after_a_missing_state_was_sealed() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    create_private_dir(&root).unwrap();
    let sealed = seal(&root).unwrap();

    create_private_dir(root.join("environments-v2")).unwrap();
    assert!(matches!(
        sealed.revalidate(),
        Err(UvCacheRootSealError::BucketChanged {
            name: "environments-v2"
        })
    ));
}

#[test]
fn selected_symlink_retargeting_cannot_redirect_the_root() {
    let temp = private_tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    let selected = temp.path().join("selected");
    create_private_dir(&first).unwrap();
    create_private_dir(&second).unwrap();
    std::os::unix::fs::symlink(&first, &selected).unwrap();
    let sealed = seal(&selected).unwrap();

    rustix::fs::unlinkat(rustix::fs::CWD, &selected, rustix::fs::AtFlags::empty()).unwrap();
    std::os::unix::fs::symlink(&second, &selected).unwrap();
    assert!(matches!(
        sealed.revalidate(),
        Err(UvCacheRootSealError::RootChanged)
    ));
}

#[test]
fn uv_lock_may_be_standard_0666_but_not_a_symlink_or_hardlink() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    create_private_dir(&root).unwrap();
    let lock = root.join(".lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, Permissions::from_mode(0o666)).unwrap();
    let sealed = seal(&root).unwrap();
    sealed.revalidate().unwrap();
    drop(sealed);

    rustix::fs::unlinkat(rustix::fs::CWD, &lock, rustix::fs::AtFlags::empty()).unwrap();
    let outside = temp.path().join("outside-lock");
    std::fs::write(&outside, b"").unwrap();
    std::os::unix::fs::symlink(&outside, &lock).unwrap();
    assert!(matches!(
        seal(&root),
        Err(UvCacheRootSealError::UnsafePath { reason, .. })
            if reason == "uv lock entry is a symlink or non-regular file"
    ));

    rustix::fs::unlinkat(rustix::fs::CWD, &lock, rustix::fs::AtFlags::empty()).unwrap();
    std::fs::hard_link(&outside, &lock).unwrap();
    assert!(matches!(
        seal(&root),
        Err(UvCacheRootSealError::UnsafePath { reason, .. })
            if reason == "uv lock entry has another hard-link attachment"
    ));
}

#[test]
fn lock_hardlink_count_is_revalidated_before_spawn() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    create_private_dir(&root).unwrap();
    let lock = root.join(".lock");
    std::fs::write(&lock, b"").unwrap();
    let sealed = seal(&root).unwrap();
    std::fs::hard_link(&lock, temp.path().join("second-lock-link")).unwrap();

    assert!(matches!(
        sealed.revalidate(),
        Err(UvCacheRootSealError::LockChanged)
    ));
}

#[test]
fn lock_attachment_is_revalidated_before_spawn() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    create_private_dir(&root).unwrap();
    let sealed = seal(&root).unwrap();
    std::fs::write(root.join(".lock"), b"").unwrap();

    assert!(matches!(
        sealed.revalidate(),
        Err(UvCacheRootSealError::LockChanged)
    ));
}

#[test]
fn verification_entry_and_depth_bounds_fail_closed() {
    let mut exhausted = TraversalBudget {
        entries: MAX_VERIFIED_ENTRIES,
    };
    assert!(matches!(
        exhausted.consume_entry(),
        Err(UvCacheRootSealError::EntryLimitExceeded)
    ));

    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    let mut nested = root.join("stale-v0");
    create_private_dir_all(&nested).unwrap();
    for _ in 0..MAX_TRAVERSAL_DEPTH {
        nested.push("d");
        create_private_dir(&nested).unwrap();
    }
    assert!(matches!(
        seal(&root),
        Err(UvCacheRootSealError::DepthLimitExceeded)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_access_and_default_acl_names_are_both_refused() {
    assert!(has_posix_acl_name(b"system.posix_acl_access\0"));
    assert!(has_posix_acl_name(b"user.test\0system.posix_acl_default\0"));
    assert!(!has_posix_acl_name(b"user.test\0security.test\0"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_extended_acl_on_a_traversed_directory_fails_closed() {
    let temp = private_tempdir().unwrap();
    let root = temp.path().join("root");
    let bucket = root.join("archive-v0");
    create_private_dir_all(&bucket).unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow add_file"])
            .arg(&bucket)
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        seal(&root),
        Err(UvCacheRootSealError::UnsafePath { .. })
    ));
}
