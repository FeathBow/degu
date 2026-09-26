use super::*;

/// An account that has not put a script anywhere consults nobody, and the
/// pane is told where one would go rather than which key to set.
#[test]
fn no_advisor_anywhere_is_reported_as_an_absence() {
    let empty = tempfile::tempdir().expect("a config home");
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let advisories = consult(
        &AdvisoryConfig::default(),
        &findings,
        &context(&home(), empty.path()),
    );
    assert_eq!(
        advisories.unavailable(),
        Some(&Unavailable::Absent(
            empty.path().join("degu").join(CONVENTION_NAME)
        ))
    );
}

fn executable(directory: &Path, name: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join(name);
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("a script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("a mode");
    path
}

/// Dropping a script at the conventional path is the whole setup. Nothing
/// is configured here, and degu finds it anyway.
#[test]
fn a_script_at_the_conventional_path_needs_no_configuration() {
    let config_home = tempfile::tempdir().expect("a config home");
    let degu = config_home.path().join("degu");
    std::fs::create_dir_all(&degu).expect("the degu config directory");
    let advisor = executable(&degu, CONVENTION_NAME, 0o700);
    assert_eq!(
        resolve_advisor(&AdvisoryConfig::default(), config_home.path()),
        Resolution::Found {
            path: advisor,
            origin: Origin::Convention
        }
    );
}

/// Naming one is an explicit choice, so it wins over whatever happens to be
/// at the conventional path.
#[test]
fn a_named_advisor_wins_over_the_convention() {
    let config_home = tempfile::tempdir().expect("a config home");
    let degu = config_home.path().join("degu");
    std::fs::create_dir_all(&degu).expect("the degu config directory");
    executable(&degu, CONVENTION_NAME, 0o700);
    let named = executable(config_home.path(), "chosen", 0o700);
    let config = AdvisoryConfig {
        command: Some(named.to_string_lossy().into_owned()),
        ..AdvisoryConfig::default()
    };
    assert_eq!(
        resolve_advisor(&config, config_home.path()),
        Resolution::Found {
            path: named,
            origin: Origin::Configured
        }
    );
}

/// An advisor runs with this account's privileges. One that another account
/// can rewrite would be degu executing their decision, so it is refused —
/// and said out loud, because a reader who put it there meant it to run.
#[test]
fn a_group_writable_advisor_is_refused_rather_than_skipped() {
    let config_home = tempfile::tempdir().expect("a config home");
    let degu = config_home.path().join("degu");
    std::fs::create_dir_all(&degu).expect("the degu config directory");
    executable(&degu, CONVENTION_NAME, 0o770);
    let Resolution::Refused { reason, .. } =
        resolve_advisor(&AdvisoryConfig::default(), config_home.path())
    else {
        panic!("a group-writable advisor was admitted");
    };
    assert!(reason.contains("writable"), "{reason}");
}

#[test]
fn a_non_executable_advisor_is_refused_rather_than_skipped() {
    let config_home = tempfile::tempdir().expect("a config home");
    let degu = config_home.path().join("degu");
    std::fs::create_dir_all(&degu).expect("the degu config directory");
    executable(&degu, CONVENTION_NAME, 0o600);
    let Resolution::Refused { reason, .. } =
        resolve_advisor(&AdvisoryConfig::default(), config_home.path())
    else {
        panic!("a non-executable advisor was admitted");
    };
    assert!(reason.contains("executable"), "{reason}");
}

/// A named path that is not there is a mistake; an absent convention is the
/// ordinary case. They must not read alike.
#[test]
fn a_named_advisor_that_is_missing_is_a_mistake_not_an_absence() {
    let config_home = tempfile::tempdir().expect("a config home");
    let config = AdvisoryConfig {
        command: Some("/nonexistent/degu-advisor".to_owned()),
        ..AdvisoryConfig::default()
    };
    let Resolution::Refused { reason, .. } = resolve_advisor(&config, config_home.path()) else {
        panic!("a missing named advisor was not reported");
    };
    assert!(reason.contains("nothing exists"), "{reason}");
}

/// The pane can be turned off entirely, and then degu asks nobody anything.
/// Off means the reader sees nothing about advisories at all, which the
/// pane needs to be able to tell apart from an advisor that ran and had
/// nothing to say.
#[test]
fn a_disabled_advisory_consults_nothing_and_says_nothing() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let config = AdvisoryConfig {
        enabled: false,
        command: Some("/bin/advisor".to_owned()),
        ..AdvisoryConfig::default()
    };
    let advisories = consult(
        &config,
        &findings,
        &context(&home(), Path::new("/nonexistent")),
    );
    assert!(advisories.disabled());
    assert_eq!(advisories.unavailable(), None);
    assert_eq!(advisories.source(), None);
    assert!(
        advisories
            .for_path(Path::new("/home/account/.cache/mystery"))
            .is_none()
    );
}

/// Running somebody's program costs them something, and a scan where degu
/// classified everything has nothing to ask about. Observed rather than
/// argued: the advisor records that it ran, and it must not have.
#[test]
fn nothing_to_ask_about_starts_no_program() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().expect("a directory");
    let witness = directory.path().join("ran");
    let advisor = directory.path().join("advisor");
    std::fs::write(
        &advisor,
        format!("#!/bin/sh\ntouch {}\n", witness.display()),
    )
    .expect("a script");
    std::fs::set_permissions(&advisor, std::fs::Permissions::from_mode(0o700)).expect("a mode");
    let config = AdvisoryConfig {
        command: Some(advisor.to_string_lossy().into_owned()),
        ..AdvisoryConfig::default()
    };

    let classified = [eligible("/home/account/.cache/pip")];
    let advisories = consult(&config, &classified, &context(&home(), directory.path()));
    assert!(!witness.exists(), "the advisor ran with nothing to ask");
    assert_eq!(advisories.unavailable(), None);

    // The same advisor does run once there is something degu cannot name,
    // so the absence above is about the question, not about the wiring.
    let unnamed = [unknown_recovery("/home/account/.cache/mystery")];
    let _ = consult(&config, &unnamed, &context(&home(), directory.path()));
    assert!(witness.exists(), "the advisor was never reachable at all");
}
