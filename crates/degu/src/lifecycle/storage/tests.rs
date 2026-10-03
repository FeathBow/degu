#[cfg(target_os = "linux")]
use super::path_mount_id;
use super::{
    TRASHROOTS_FILE, ensure_managed_trash_root, ensure_managed_trash_root_with_sync,
    is_state_trash_root, read_registered_trash_roots, register_trash_root,
    register_trash_root_with_sync, resolve_mount_owner_anchor_with, trash_dir_state, trash_roots,
};
use degu_core::ecosystem::DetectCtx;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn fresh_state_trash_root_uses_lexical_identity_until_its_parent_exists() {
    let home = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let state = base.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let ctx = DetectCtx::for_test(
        home.path().to_path_buf(),
        [("XDG_STATE_HOME".to_owned(), state.as_os_str().to_owned())],
    );
    let root = trash_dir_state(&ctx);

    assert!(!root.parent().unwrap().exists());
    assert!(is_state_trash_root(&ctx, &root));
}

#[test]
fn mount_anchor_walk_keeps_the_last_confirmed_anchor_after_probe_failure() {
    let dir = tempfile::tempdir().unwrap();
    let accepted = dir.path().join("accepted");
    let source = accepted.join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::set_permissions(&accepted, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut probed = Vec::new();

    let anchor = resolve_mount_owner_anchor_with(&source, 77, |current| {
        probed.push(current.to_path_buf());
        if current == accepted {
            Ok(77)
        } else {
            Err("injected mount inspection failure".to_string())
        }
    })
    .unwrap();

    assert_eq!(anchor, accepted);
    assert_eq!(probed, vec![accepted, dir.path().to_path_buf()]);
}

#[cfg(target_os = "linux")]
#[test]
fn mount_identity_probe_does_not_require_directory_read_permission() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let result = path_mount_id(&path);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(result.is_ok(), "{result:?}");
}

/// The trash is private; the namespace it sits in is the one setup publishes
/// the activation anchor under.
///
/// `<state>/degu` is both, and provisioning requires exactly 0755 of it.
/// Creating it private blocks setup for good, because provisioning is
/// create-only and never repairs. Privacy belongs to the entries inside,
/// which carry their own modes.
#[test]
fn the_trash_is_private_inside_a_namespace_setup_can_publish_under() {
    let dir = tempfile::tempdir().unwrap();
    let root = ensure_managed_trash_root(&dir.path().join("degu/trash"), "trash").unwrap();

    let mode = std::fs::symlink_metadata(&root).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o700, "the trash itself stays owner-only");
    let parent_mode = std::fs::symlink_metadata(root.parent().unwrap())
        .unwrap()
        .mode()
        & 0o777;
    assert_eq!(
        parent_mode, 0o755,
        "provisioning requires this component to be exactly 0755"
    );
}

/// An account an earlier version left at 0700 is migrated, not refused.
///
/// Provisioning wants this component to be exactly 0755. Creating it private
/// blocks setup for good, because provisioning is create-only and never
/// repairs, so the namespace has to be brought forward here. The entries
/// inside are narrowed before it widens, never after.
#[test]
fn an_existing_private_namespace_is_migrated_and_its_entries_narrowed_first() {
    let base = tempfile::tempdir().unwrap();
    let parent = base.path().join("degu");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["lock", "ops.jsonl", "trashroots"] {
        std::fs::write(parent.join(name), b"").unwrap();
        std::fs::set_permissions(parent.join(name), std::fs::Permissions::from_mode(0o644))
            .unwrap();
    }

    super::validation::ensure_state_parent(&parent).unwrap();

    assert_eq!(
        std::fs::symlink_metadata(&parent).unwrap().mode() & 0o777,
        0o755,
        "the namespace must reach the mode provisioning requires"
    );
    for name in ["lock", "ops.jsonl", "trashroots"] {
        assert_eq!(
            std::fs::symlink_metadata(parent.join(name)).unwrap().mode() & 0o777,
            0o600,
            "{name} must not stay readable inside a published namespace"
        );
    }
}

/// Below the account base a symlink is not a legitimate component, and following one
/// would reach a namespace outside the chain provisioning will authenticate. The link
/// target here holds a namespace that would otherwise be migrated, so the assertions
/// fail if the walk ever follows it.
#[test]
fn publishing_through_a_symlinked_ancestor_creates_and_changes_nothing() {
    let base = tempfile::tempdir().unwrap();
    let elsewhere = base.path().join("elsewhere");
    let victim = elsewhere.join("state").join("degu");
    std::fs::create_dir_all(&victim).unwrap();
    let lock = victim.join("lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let local = base.path().join(".local");
    std::os::unix::fs::symlink(&elsewhere, &local).unwrap();

    super::validation::publish_existing_namespace(base.path(), &local.join("state").join("degu"))
        .unwrap();

    assert_eq!(
        std::fs::symlink_metadata(&victim).unwrap().mode() & 0o777,
        0o700,
        "a namespace reachable only through the link may not be published"
    );
    assert_eq!(
        std::fs::symlink_metadata(&lock).unwrap().mode() & 0o777,
        0o644,
        "nor may its entries be narrowed through one"
    );
}

/// The mode is what tells provisioning anyone could have written here, and
/// provisioning refuses the namespace for it. Widening it would take that evidence
/// away and leave the namespace looking like one an earlier version had merely kept
/// private.
#[test]
fn publishing_a_shared_writable_namespace_leaves_its_mode_as_evidence() {
    let base = tempfile::tempdir().unwrap();
    let namespace = base.path().join("degu");
    std::fs::create_dir(&namespace).unwrap();
    let lock = namespace.join("lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o777)).unwrap();

    super::validation::publish_existing_namespace(base.path(), &namespace).unwrap();

    assert_eq!(
        std::fs::symlink_metadata(&namespace).unwrap().mode() & 0o7777,
        0o777,
        "a namespace anyone can write to is not one to publish"
    );
    assert_eq!(
        std::fs::symlink_metadata(&lock).unwrap().mode() & 0o777,
        0o644,
        "and its entries are not ours to narrow either"
    );
}

/// The system path above an account base is authenticated as well, by the walk that
/// resolves the base. A directory anyone can write to up there could have the base
/// replaced under it, so nothing below it is a namespace to publish — and it is the
/// only part of the chain no no-follow open would catch.
#[test]
fn publishing_below_a_shared_writable_directory_above_the_base_changes_nothing() {
    let outer = tempfile::tempdir().unwrap();
    let home = outer.path().join("home");
    let namespace = home.join("degu");
    std::fs::create_dir_all(&namespace).unwrap();
    std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

    super::validation::publish_existing_namespace(&home, &namespace).unwrap();

    assert_eq!(
        std::fs::symlink_metadata(&namespace).unwrap().mode() & 0o777,
        0o700,
        "a base reached through a directory anyone can write to is not authenticated"
    );
}

/// Provisioning permits no shared write at all on a component it manages, not even on
/// a sticky one, so neither does this: the sticky bit decides who may remove an entry,
/// not who may add one. This is the case the shared `directory_grants_foreign_mutation`
/// predicate would have let through.
#[test]
fn publishing_under_a_sticky_shared_writable_ancestor_changes_nothing() {
    let base = tempfile::tempdir().unwrap();
    let local = base.path().join(".local");
    let namespace = local.join("state").join("degu");
    std::fs::create_dir_all(&namespace).unwrap();
    std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o1777)).unwrap();

    super::validation::publish_existing_namespace(base.path(), &namespace).unwrap();

    assert_eq!(
        std::fs::symlink_metadata(&namespace).unwrap().mode() & 0o777,
        0o700,
        "a sticky bit does not make an ancestor anyone can write to publishable"
    );
}

/// Provisioning authenticates the whole chain and refuses a group-writable ancestor.
/// The migration runs first, so it has to reach that refusal with the namespace as it
/// found it rather than published inside a directory the account does not control
/// alone.
#[test]
fn publishing_under_a_shared_writable_ancestor_changes_nothing() {
    let base = tempfile::tempdir().unwrap();
    let local = base.path().join(".local");
    let namespace = local.join("state").join("degu");
    std::fs::create_dir_all(&namespace).unwrap();
    std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o770)).unwrap();

    super::validation::publish_existing_namespace(base.path(), &namespace).unwrap();

    assert_eq!(
        std::fs::symlink_metadata(&namespace).unwrap().mode() & 0o777,
        0o700,
        "an ancestor provisioning will refuse must not have had the namespace widened under it"
    );
}

/// An absent namespace is provisioning's to create, which it does at the published
/// mode with private ancestors. Creating it here by pathname would publish ancestors
/// at whatever the ambient umask allows, and provisioning refuses a group-writable
/// ancestor — so a fresh account under `umask 002` would be blocked by directories
/// account setup had just created for it.
#[test]
fn publishing_an_absent_namespace_creates_nothing() {
    let base = tempfile::tempdir().unwrap();
    let namespace = base.path().join(".local").join("state").join("degu");

    super::validation::publish_existing_namespace(base.path(), &namespace).unwrap();

    assert!(
        !base.path().join(".local").exists(),
        "no ancestor was created"
    );
}

/// The case that made account setup fail: the namespace is there, owner-only, and
/// provisioning requires it at exactly 0755.
#[test]
fn publishing_an_existing_private_namespace_reaches_the_published_mode() {
    let base = tempfile::tempdir().unwrap();
    let namespace = base.path().join("degu");
    std::fs::create_dir(&namespace).unwrap();
    std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lock = namespace.join("lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();

    super::validation::publish_existing_namespace(base.path(), &namespace).unwrap();

    assert_eq!(
        std::fs::symlink_metadata(&namespace).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::symlink_metadata(&lock).unwrap().mode() & 0o077,
        0,
        "the lock relied on a private parent for its privacy"
    );
}

/// A link where the namespace belongs is refused before anything is chmodded.
#[test]
fn a_symlinked_namespace_is_refused_before_its_entries_are_touched() {
    let base = tempfile::tempdir().unwrap();
    let elsewhere = base.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let victim = elsewhere.join("ops.jsonl");
    std::fs::write(&victim, b"").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let parent = base.path().join("degu");
    std::os::unix::fs::symlink(&elsewhere, &parent).unwrap();

    assert!(super::validation::ensure_state_parent(&parent).is_err());
    assert_eq!(
        std::fs::symlink_metadata(&victim).unwrap().mode() & 0o777,
        0o644,
        "the refusal must come before anything through the link is changed"
    );
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
