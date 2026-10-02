use super::*;
use crate::native::{NativeRunReport, NativeRunnerError};
use std::fs::Permissions;
use std::os::unix::fs::{PermissionsExt, symlink};

mod version_output;

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

#[cfg(target_os = "macos")]
const NATIVE_MAGIC: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
#[cfg(not(target_os = "macos"))]
const NATIVE_MAGIC: [u8; 4] = *b"\x7fELF";

/// Native admission reads the leading magic only. A fixture therefore declares
/// the format it claims instead of copying a system binary, which would also
/// make it runnable — something no probe test asserts and which the host
/// operating system is free to withdraw from copies.
fn native_fixture(directory: &Path) -> PathBuf {
    let executable = directory.join("uv-fixture");
    std::fs::write(&executable, NATIVE_MAGIC).unwrap();
    std::fs::set_permissions(&executable, Permissions::from_mode(0o700)).unwrap();
    executable
}

fn probe_fixture(
    path: PathBuf,
    version: UvVersion,
) -> Result<ProbedUvExecutable, UvExecutableProbeError> {
    probe_uv_executable_with(selection(path), &mut |_, _| Ok(version))
}

#[test]
fn probe_outcomes_map_to_a_supported_version_or_a_closed_failure() {
    assert_eq!(
        parsed_probe_version(&NativeRunOutcome::Success(AUDITED_UV_PRUNE_VERSION)).unwrap(),
        AUDITED_UV_PRUNE_VERSION
    );
    assert_eq!(
        parsed_probe_version(&NativeRunOutcome::Success(MINIMUM_UV_VERSION)).unwrap(),
        MINIMUM_UV_VERSION
    );

    let too_old = UvVersion::new(0, 8, 18);
    let unparsable = parse_uv_version(b"uv 0.8.19 extra\n").expect_err("fixture must not parse");
    let cases: [(NativeRunOutcome<UvVersion, UvVersionParseError>, &str); 6] = [
        (NativeRunOutcome::Success(too_old), "too old"),
        (
            NativeRunOutcome::OutputParseFailure(unparsable),
            "malformed",
        ),
        (NativeRunOutcome::ExitFailure { code: Some(1) }, "failed"),
        (
            NativeRunOutcome::Signal {
                signal: Some(libc::SIGKILL),
            },
            "signalled",
        ),
        (NativeRunOutcome::Timeout, "timed out"),
        (NativeRunOutcome::OutputTruncated, "truncated"),
    ];
    for (outcome, label) in cases {
        let error = parsed_probe_version(&outcome).expect_err("outcome must fail");
        let matched = match label {
            "too old" => matches!(
                error,
                UvExecutableProbeError::VersionTooOld { found, minimum }
                    if found == too_old && minimum == MINIMUM_UV_VERSION
            ),
            "malformed" => matches!(error, UvExecutableProbeError::InvalidOutput(_)),
            "failed" => matches!(error, UvExecutableProbeError::ExitFailure { code: Some(1) }),
            "signalled" => matches!(error, UvExecutableProbeError::Signal { signal: Some(_) }),
            "timed out" => matches!(error, UvExecutableProbeError::Timeout),
            "truncated" => matches!(error, UvExecutableProbeError::OutputTruncated),
            _ => unreachable!(),
        };
        assert!(matched, "{label}: unexpected error {error:?}");
    }
}

#[test]
fn the_token_reports_the_version_the_probe_produced() {
    let temp = private_tempdir();
    let probed = probe_fixture(native_fixture(temp.path()), AUDITED_UV_PRUNE_VERSION).unwrap();
    assert_eq!(probed.version(), AUDITED_UV_PRUNE_VERSION);
    probed.revalidate_path().unwrap();
}

#[test]
fn a_symlink_selection_revalidates_and_its_snapshot_dies_with_the_token() {
    let temp = private_tempdir();
    let executable = native_fixture(temp.path());
    let link = temp.path().join("selected-uv");
    symlink(&executable, &link).unwrap();

    let probed = probe_fixture(link.clone(), MINIMUM_UV_VERSION).unwrap();
    assert_eq!(probed.selection().as_path(), link);
    assert_eq!(probed.version(), MINIMUM_UV_VERSION);
    probed.revalidate_path().unwrap();
    let snapshot = probed.executable.snapshot_path().to_path_buf();
    assert!(snapshot.is_file());
    drop(probed);
    assert!(!snapshot.exists(), "private executable snapshot leaked");
}

#[test]
fn unsafe_mode_and_ancestor_are_refused_before_execution() {
    let temp = private_tempdir();
    let executable = native_fixture(temp.path());
    std::fs::set_permissions(&executable, Permissions::from_mode(0o722)).unwrap();
    assert!(matches!(
        probe_fixture(executable.clone(), MINIMUM_UV_VERSION),
        Err(UvExecutableProbeError::UnsafePath { reason, .. })
            if reason == "executable is group- or world-writable"
    ));

    std::fs::set_permissions(&executable, Permissions::from_mode(0o410)).unwrap();
    assert!(matches!(
        probe_fixture(executable.clone(), MINIMUM_UV_VERSION),
        Err(UvExecutableProbeError::UnsafePath { reason, .. })
            if reason == "effective user cannot execute selected file"
    ));

    std::fs::set_permissions(&executable, Permissions::from_mode(0o700)).unwrap();
    let shared = temp.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, Permissions::from_mode(0o777)).unwrap();
    let nested = native_fixture(&shared);
    assert!(matches!(
        probe_fixture(nested, MINIMUM_UV_VERSION),
        Err(UvExecutableProbeError::UnsafePath { reason, .. })
            if reason == "ancestor namespace grants foreign mutation authority"
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
    let executable = native_fixture(temp.path());
    let opened = open_selected_executable(&selection(executable.clone())).unwrap();
    let snapshot = snapshot_executable(&opened).unwrap();
    std::fs::set_permissions(&executable, Permissions::from_mode(0o500)).unwrap();
    assert!(matches!(
        require_source_unchanged(&opened),
        Err(UvExecutableProbeError::PathChanged)
    ));
    drop(snapshot);
}

fn run_held_snapshot(
    probed: &ProbedUvExecutable,
) -> Result<NativeRunReport<UvVersion, UvVersionParseError>, NativeRunnerError> {
    let request = NativeActionRequest::new(
        NativeActionIdentity::new("uv", "version-probe").unwrap(),
        probed.selection().clone(),
        [OsString::from("-V")],
        NativeEnvironmentRequest::clear(),
        NativeProcessContract::AuditedCooperativeProcessGroup,
        VERSION_PROBE_TIMEOUT,
        VERSION_OUTPUT_LIMIT,
        VERSION_OUTPUT_LIMIT,
        [],
    )
    .unwrap();
    prepare_native_action_from_held(request, probed.executable.duplicate().unwrap())
        .unwrap()
        .execute(parse_uv_version)
        .result()
}

#[test]
fn the_held_binding_admits_an_untouched_snapshot_and_refuses_a_replaced_one() {
    let temp = private_tempdir();
    let probed = probe_fixture(native_fixture(temp.path()), MINIMUM_UV_VERSION).unwrap();
    let snapshot = probed.executable.snapshot_path().to_path_buf();

    // Whatever the fixture does once it runs, the binding must not be what
    // refused it. Without this half, a check that could never find its
    // attachment would be indistinguishable from one that works.
    let untouched = run_held_snapshot(&probed);
    assert!(
        !matches!(untouched, Err(NativeRunnerError::ExecutableBinding(_))),
        "an untouched snapshot must pass the held binding check: {untouched:?}"
    );

    let displaced = snapshot.with_file_name("held-original");
    let replacement_out = temp.path().join("snapshot-replacement");
    std::fs::rename(&snapshot, &displaced).unwrap();
    std::fs::write(&snapshot, NATIVE_MAGIC).unwrap();
    std::fs::set_permissions(&snapshot, Permissions::from_mode(0o500)).unwrap();
    assert!(matches!(
        run_held_snapshot(&probed),
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
    let executable = native_fixture(temp.path());
    let replacement_source = temp.path().join("replacement-source");
    std::fs::copy(&executable, &replacement_source).unwrap();
    std::fs::set_permissions(&replacement_source, Permissions::from_mode(0o700)).unwrap();
    let displaced = temp.path().join("displaced");
    let selected = executable.clone();
    assert!(matches!(
        probe_uv_executable_with(selection(selected), &mut |_, _| {
            std::fs::rename(&executable, &displaced).unwrap();
            std::fs::rename(&replacement_source, &executable).unwrap();
            Ok(MINIMUM_UV_VERSION)
        }),
        Err(UvExecutableProbeError::PathChanged)
    ));
}

mod attributes;
