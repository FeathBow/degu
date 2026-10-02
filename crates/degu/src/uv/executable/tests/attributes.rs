use super::*;

#[cfg(target_os = "macos")]
#[test]
fn macos_acl_and_execution_security_xattrs_fail_closed() {
    let acl_temp = private_tempdir();
    let acl_executable = native_fixture(acl_temp.path());
    let planted = {
        let _shared = crate::fork_gate::forking();
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(&acl_executable)
            .status()
            .unwrap()
    };
    assert!(planted.success());
    assert!(matches!(
        open_selected_executable(&selection(acl_executable)),
        Err(UvExecutableProbeError::UnsafePath { .. })
    ));

    let xattr_temp = private_tempdir();
    let xattr_executable = native_fixture(xattr_temp.path());
    plant_xattr(&xattr_executable, "com.apple.quarantine", "0081;degu-test");
    assert!(matches!(
        open_selected_executable(&selection(xattr_executable)),
        Err(UvExecutableProbeError::UnpreservedXattr { .. })
    ));
}

#[cfg(target_os = "macos")]
fn plant_xattr(path: &Path, name: &str, value: &str) {
    let _shared = crate::fork_gate::forking();
    let planted = std::process::Command::new("/usr/bin/xattr")
        .args(["-w", name, value])
        .arg(path)
        .status()
        .unwrap();
    assert!(planted.success(), "failed to plant {name}");
}

/// macOS attaches `com.apple.provenance` to what it extracted, and the official uv
/// release carries it, so refusing every attribute refused the supported binary before
/// the version probe. Dropping provenance from the snapshot changes nothing about how
/// the snapshot runs. Quarantine does change it, and a download commonly carries both,
/// so the droppable one must not let the other through behind it.
#[cfg(target_os = "macos")]
#[test]
fn macos_provenance_is_droppable_but_never_beside_quarantine() {
    let temp = private_tempdir();
    let executable = native_fixture(temp.path());
    plant_xattr(&executable, "com.apple.provenance", "degu-test");
    open_selected_executable(&selection(executable.clone()))
        .expect("provenance alone leaves nothing a snapshot would have to preserve");

    plant_xattr(&executable, "com.apple.quarantine", "0081;degu-test");
    match open_selected_executable(&selection(executable)) {
        Err(UvExecutableProbeError::UnpreservedXattr { name, .. }) => {
            assert_eq!(name, "com.apple.quarantine");
        }
        Err(other) => panic!("quarantine must be refused as an attribute, not as {other}"),
        Ok(_) => panic!("a quarantined executable must not be accepted"),
    }
}

/// The name list is NUL-separated and NUL-terminated, so its last split is empty. An
/// empty name is on no allowlist, and counting it would refuse every file that has any
/// attribute at all for an attribute that does not exist.
#[test]
fn a_name_list_terminator_is_not_a_name() {
    assert_eq!(first_undroppable_xattr(b""), None);
    assert_eq!(
        first_undroppable_xattr(b"com.example.one\0"),
        Some("com.example.one".to_owned())
    );
    assert_eq!(
        first_undroppable_xattr(b"com.example.one\0com.example.two\0"),
        Some("com.example.one".to_owned()),
        "the first name a snapshot could not carry is the one reported"
    );
}
