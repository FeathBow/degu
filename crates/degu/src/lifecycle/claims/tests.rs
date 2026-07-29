use super::{interrupted_purge_claims, prepare_claims_dir, validate_existing_claims_dir};
use std::os::unix::fs::symlink;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn claims_directory_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let claims = prepare_claims_dir(dir.path()).unwrap();

    let mode = std::fs::symlink_metadata(claims).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn group_writable_claims_directory_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let claims = dir.path().join(".claims");
    std::fs::create_dir(&claims).unwrap();
    std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o770)).unwrap();

    let error = validate_existing_claims_dir(dir.path()).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("group- or world-writable"));
}

#[test]
fn only_empty_numeric_files_are_reservation_markers() {
    let dir = tempfile::tempdir().unwrap();
    let claims = prepare_claims_dir(dir.path()).unwrap();
    std::fs::write(claims.join("0001"), b"").unwrap();
    std::fs::write(claims.join("0002"), b"preserved data").unwrap();
    std::fs::create_dir(claims.join("0003")).unwrap();
    symlink(dir.path().join("external"), claims.join("0004")).unwrap();
    std::fs::write(claims.join("purge-token"), b"cache").unwrap();

    let interrupted = interrupted_purge_claims(dir.path()).unwrap();

    assert_eq!(
        interrupted,
        vec![
            claims.join("0002"),
            claims.join("0003"),
            claims.join("0004"),
            claims.join("purge-token")
        ]
    );
}
