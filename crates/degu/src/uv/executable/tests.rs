use super::*;
use std::fs::Permissions;
use std::os::unix::fs::{PermissionsExt, symlink};

// The workspace CI runs under umask 002, where `tempfile` would create a
// group-writable base directory that the ancestor-namespace guard rejects.
// Pin every fixture root to 0o700 so the guard sees a private tree regardless
// of the ambient umask; tests that need a shared-writable path set it explicitly.
fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new().tempdir().unwrap();
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
    dir
}

fn selection(path: PathBuf) -> NativeExecutableSelection {
    NativeExecutableSelection::explicit(path).unwrap()
}

fn copied_binary(directory: &Path, source: &Path) -> PathBuf {
    let executable = directory.join("uv-fixture");
    std::fs::copy(source, &executable).unwrap();
    std::fs::set_permissions(&executable, Permissions::from_mode(0o700)).unwrap();
    executable
}

fn probe_fixture(
    path: PathBuf,
    mode: &str,
    after_probe: &mut impl FnMut(),
) -> Result<ProbedUvExecutable, UvExecutableProbeError> {
    let arguments = match mode {
        "minimum" => vec![OsString::from("uv 0.8.19")],
        "old" => vec![OsString::from("uv 0.8.18")],
        "malformed" => vec![OsString::from("uv 0.8.19 extra")],
        "failure" => Vec::new(),
        "timeout" => vec![OsString::from("30")],
        "large" => vec![OsString::from(format!(
            "uv {}.0.0",
            "9".repeat(VERSION_OUTPUT_LIMIT * 2)
        ))],
        other => panic!("unknown fixture mode: {other:?}"),
    };
    probe_uv_executable_with(
        selection(path),
        arguments,
        NativeEnvironmentRequest::clear(),
        after_probe,
    )
}

#[test]
fn exact_stable_versions_parse_and_minimum_is_inclusive() {
    assert_eq!(parse_uv_version(b"uv 0.8.19\n"), Ok(MINIMUM_UV_VERSION));
    assert_eq!(
        parse_uv_version(b"uv 12.34.56\n"),
        Ok(UvVersion {
            major: 12,
            minor: 34,
            patch: 56
        })
    );
}

#[test]
fn ambiguous_or_nonstable_version_output_fails_closed() {
    for invalid in [
        &b"0.8.19\n"[..],
        b"uv 0.8.19",
        b"uv 0.8.19\r\n",
        b"uv 0.8.19 extra\n",
        b"uv 0.8.19-alpha.1\n",
        b"uv 0.8.19+local\n",
        b"uv 00.8.19\n",
        b"uv 0.8\n",
        b"uv 0.8.19\nother\n",
        b"uv 18446744073709551616.0.0\n",
        b"\xff\n",
    ] {
        assert!(parse_uv_version(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn held_native_binary_probe_accepts_minimum_and_revalidates_symlink() {
    let temp = private_tempdir();
    let executable = copied_binary(temp.path(), Path::new("/bin/echo"));
    let link = temp.path().join("selected-uv");
    symlink(&executable, &link).unwrap();

    let probed = probe_fixture(link.clone(), "minimum", &mut || {}).unwrap();
    assert_eq!(probed.selection().as_path(), link);
    assert_eq!(probed.version(), MINIMUM_UV_VERSION);
    probed.revalidate_path().unwrap();
    let snapshot = probed.executable.snapshot_path().to_path_buf();
    assert!(snapshot.is_file());
    drop(probed);
    assert!(!snapshot.exists(), "private executable snapshot leaked");
}

#[test]
fn old_malformed_failed_timed_out_and_large_probes_fail_closed() {
    for (mode, source) in [
        ("old", "/bin/echo"),
        ("malformed", "/bin/echo"),
        ("failure", "/usr/bin/false"),
        ("timeout", "/bin/sleep"),
        ("large", "/bin/echo"),
    ] {
        let temp = private_tempdir();
        let executable = copied_binary(temp.path(), Path::new(source));
        let error = probe_fixture(executable, mode, &mut || {})
            .err()
            .expect("probe must fail");
        let matched = match mode {
            "old" => matches!(error, UvExecutableProbeError::VersionTooOld { .. }),
            "malformed" => matches!(error, UvExecutableProbeError::InvalidOutput(_)),
            "failure" => matches!(error, UvExecutableProbeError::ExitFailure { .. }),
            "timeout" => matches!(error, UvExecutableProbeError::Timeout),
            "large" => matches!(error, UvExecutableProbeError::OutputTruncated),
            _ => unreachable!(),
        };
        assert!(matched, "mode {mode:?}: unexpected error {error:?}");
    }
}

#[test]
fn unsafe_mode_and_ancestor_are_refused_before_execution() {
    let temp = private_tempdir();
    let executable = copied_binary(temp.path(), Path::new("/bin/echo"));
    std::fs::set_permissions(&executable, Permissions::from_mode(0o722)).unwrap();
    assert!(matches!(
        probe_fixture(executable.clone(), "minimum", &mut || {}),
        Err(UvExecutableProbeError::UnsafePath { reason, .. })
            if reason == "executable is group- or world-writable"
    ));

    std::fs::set_permissions(&executable, Permissions::from_mode(0o410)).unwrap();
    assert!(matches!(
        probe_fixture(executable.clone(), "minimum", &mut || {}),
        Err(UvExecutableProbeError::UnsafePath { reason, .. })
            if reason == "effective user cannot execute selected file"
    ));

    std::fs::set_permissions(&executable, Permissions::from_mode(0o700)).unwrap();
    let shared = temp.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, Permissions::from_mode(0o777)).unwrap();
    let nested = copied_binary(&shared, Path::new("/bin/echo"));
    assert!(matches!(
        probe_fixture(nested, "minimum", &mut || {}),
        Err(UvExecutableProbeError::UnsafePath { reason, .. })
            if reason == "ancestor namespace grants foreign mutation authority"
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_acl_and_execution_security_xattrs_fail_closed() {
    let acl_temp = private_tempdir();
    let acl_executable = copied_binary(acl_temp.path(), Path::new("/bin/echo"));
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(&acl_executable)
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        open_selected_executable(&selection(acl_executable)),
        Err(UvExecutableProbeError::UnsafePath { .. })
    ));

    let xattr_temp = private_tempdir();
    let xattr_executable = copied_binary(xattr_temp.path(), Path::new("/bin/echo"));
    assert!(
        std::process::Command::new("/usr/bin/xattr")
            .args(["-w", "com.apple.quarantine", "0081;degu-test"])
            .arg(&xattr_executable)
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        open_selected_executable(&selection(xattr_executable)),
        Err(UvExecutableProbeError::UnsafePath { .. })
    ));
}

#[test]
fn snapshot_parent_chain_rejects_a_shared_writable_ancestor() {
    let temp = private_tempdir();
    let shared = temp.path().join("shared");
    let private = shared.join("private");
    std::fs::create_dir(&shared).unwrap();
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&shared, Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(&private, Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        validate_snapshot_parent_chain(&private),
        Err(UvExecutableProbeError::UnsafePath { .. })
    ));
}

#[test]
fn source_change_after_snapshot_is_refused_before_probe_execution() {
    let temp = private_tempdir();
    let executable = copied_binary(temp.path(), Path::new("/bin/echo"));
    let opened = open_selected_executable(&selection(executable.clone())).unwrap();
    let snapshot = snapshot_executable(&opened).unwrap();
    std::fs::set_permissions(&executable, Permissions::from_mode(0o500)).unwrap();
    assert!(matches!(
        require_source_unchanged(&opened),
        Err(UvExecutableProbeError::PathChanged)
    ));
    drop(snapshot);
}

#[test]
fn runner_refuses_snapshot_path_replacement_against_held_identity() {
    let temp = private_tempdir();
    let executable = copied_binary(temp.path(), Path::new("/bin/echo"));
    let probed = probe_fixture(executable, "minimum", &mut || {}).unwrap();
    let snapshot = probed.executable.snapshot_path().to_path_buf();
    let displaced = snapshot.with_file_name("held-original");
    let replacement_out = temp.path().join("snapshot-replacement");
    std::fs::rename(&snapshot, &displaced).unwrap();
    std::fs::copy("/bin/echo", &snapshot).unwrap();
    std::fs::set_permissions(&snapshot, Permissions::from_mode(0o500)).unwrap();

    let request = NativeActionRequest::new(
        NativeActionIdentity::new("uv", "version-probe").unwrap(),
        probed.selection().clone(),
        [OsString::from("uv 0.8.19")],
        NativeEnvironmentRequest::clear(),
        NativeProcessContract::AuditedCooperativeProcessGroup,
        VERSION_PROBE_TIMEOUT,
        VERSION_OUTPUT_LIMIT,
        VERSION_OUTPUT_LIMIT,
        [],
    )
    .unwrap();
    let prepared =
        prepare_native_action_from_held(request, probed.executable.duplicate().unwrap()).unwrap();
    assert!(matches!(
        prepared.execute(parse_uv_version).result(),
        Err(NativeRunnerError::ExecutableBinding(_))
    ));

    std::fs::rename(&snapshot, &replacement_out).unwrap();
    std::fs::rename(&displaced, &snapshot).unwrap();
    drop(probed);
    assert!(!snapshot.exists());
}

#[test]
fn scripts_are_refused_before_any_interpreter_can_run() {
    let temp = private_tempdir();
    let script = temp.path().join("uv-script");
    std::fs::write(&script, b"#!/bin/sh\nprintf 'uv 99.0.0\\n'\n").unwrap();
    std::fs::set_permissions(&script, Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        probe_uv_executable(selection(script)),
        Err(UvExecutableProbeError::NotNativeBinary(_))
    ));
}

#[test]
fn path_replacement_after_probe_cannot_mint_a_token() {
    let temp = private_tempdir();
    let executable = copied_binary(temp.path(), Path::new("/bin/echo"));
    let replacement_source = temp.path().join("replacement-source");
    std::fs::copy(&executable, &replacement_source).unwrap();
    std::fs::set_permissions(&replacement_source, Permissions::from_mode(0o700)).unwrap();
    let displaced = temp.path().join("displaced");
    let selected = executable.clone();
    let mut replace = || {
        std::fs::rename(&executable, &displaced).unwrap();
        std::fs::rename(&replacement_source, &executable).unwrap();
    };
    assert!(matches!(
        probe_fixture(selected, "minimum", &mut replace),
        Err(UvExecutableProbeError::PathChanged)
    ));
}
