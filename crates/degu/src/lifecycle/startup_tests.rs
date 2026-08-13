use super::*;
use degu_core::store_activation::StoreActivationError;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn context() -> (tempfile::TempDir, DetectCtx) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let home = temp.path().canonicalize().unwrap();
    let state = home.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(state.join("degu")).unwrap();
    std::fs::set_permissions(state.join("degu"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let ctx = DetectCtx::for_test(
        home,
        [(OsString::from("XDG_STATE_HOME"), state.into_os_string())],
    );
    (temp, ctx)
}

#[test]
fn missing_fixed_anchor_blocks_without_creating_a_store() {
    let (_temp, ctx) = context();
    let desired = std::fs::canonicalize(ctx.xdg_state())
        .unwrap()
        .join("degu/sealed-staging");
    let missing = ctx.home.join("system-anchor");
    let error = storage::sealed_staging_store_for_mutation_with(&ctx, |actual| {
        assert_eq!(actual, desired);
        Err(StoreActivationError::AnchorNotProvisioned {
            path: missing.clone(),
        })
    })
    .err()
    .expect("missing anchor unexpectedly allowed a store");

    assert!(
        format!("{error:#}").contains("not provisioned"),
        "unexpected error: {error:#}"
    );
    assert!(!missing.exists());
    assert!(!desired.exists());
}

#[test]
fn production_locator_selection_has_no_home_or_xdg_input() {
    let first = degu_core::store_activation::ActivationAnchorLocator::for_current_euid().unwrap();
    let changed_home = Path::new("/tmp/degu-home-trap");
    let changed_state = Path::new("/tmp/degu-xdg-trap");
    let ctx = DetectCtx::for_test(
        changed_home.to_path_buf(),
        [(
            OsString::from("XDG_STATE_HOME"),
            changed_state.as_os_str().to_os_string(),
        )],
    );
    assert_ne!(storage::sealed_staging_store_path(&ctx), first.as_path());
    assert_eq!(
        degu_core::store_activation::ActivationAnchorLocator::for_current_euid()
            .unwrap()
            .as_path(),
        first.as_path()
    );
}

#[test]
fn desired_store_remains_the_canonical_current_xdg_locator_before_activation() {
    let (_temp, ctx) = context();
    let expected = std::fs::canonicalize(ctx.xdg_state())
        .unwrap()
        .join("degu/sealed-staging");
    let mut observed = PathBuf::new();
    let error = storage::sealed_staging_store_for_mutation_with(&ctx, |desired| {
        observed = desired.to_path_buf();
        Err(StoreActivationError::NotResumable)
    })
    .err()
    .expect("sentinel activation failure unexpectedly succeeded");
    assert!(format!("{error:#}").contains("not in a resumable"));
    assert_eq!(observed, expected);
}
