use crate::pty::{PtyRun, run as run_pty};

pub(super) use crate::common::isolated_config_home as test_config_home;
pub(super) use crate::common::isolated_degu as degu;

pub(super) fn fake_conda_env(home: &tempfile::TempDir) -> std::path::PathBuf {
    let env = home.path().join("miniconda3/envs/myenv");
    std::fs::create_dir_all(env.join("conda-meta")).unwrap();
    std::fs::write(env.join("conda-meta/somepkg.json"), "{}").unwrap();
    env
}

pub(super) fn canonical_path_string(path: &std::path::Path) -> String {
    path.canonicalize().unwrap().to_string_lossy().into_owned()
}

pub(super) fn run_clean(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    args: &[&str],
) -> std::process::Output {
    degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(args)
        .output()
        .unwrap()
}

/// Extracts the review preview command scan printed, pins its exact shape,
/// and returns its arguments as the shell would pass them to degu.
pub(super) fn review_preview_args(
    scan_stdout: &str,
    expected: &str,
    home: &std::path::Path,
) -> Vec<String> {
    let command = scan_stdout
        .lines()
        .find_map(|line| line.find("degu clean ").map(|at| line[at..].trim_end()))
        .unwrap_or_else(|| panic!("no review preview command in stdout: {scan_stdout}"));
    assert_eq!(command, expected, "stdout: {scan_stdout}");
    command
        .split(' ')
        .skip(1)
        .map(|arg| match arg.strip_prefix("~/") {
            Some(rest) => home.join(rest).to_str().unwrap().to_string(),
            None => arg.to_string(),
        })
        .collect()
}

/// Mode 0o000 does not bar root, so permission-denial fixtures cannot bite.
#[cfg(unix)]
pub(super) fn root_ignores_dir_modes() -> bool {
    rustix::process::geteuid().is_root()
}

#[cfg(unix)]
pub(super) fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub(super) fn run_terminal_clean_path(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    path: &std::path::Path,
) -> std::process::Output {
    let body = r#"
spawn -noecho $env(DEGU_BIN) clean --dry-run --path $env(CLEAN_PATH)
"#;
    let extra_env = [("CLEAN_PATH", path.as_os_str())];
    run_pty(PtyRun {
        body,
        home: home.path(),
        config_home: test_config_home(),
        state_home: state.path(),
        extra_env: &extra_env,
    })
}
