use crate::relocate_support::generated_script;

#[test]
fn relocate_script_preserves_failure_when_an_export_is_readonly() {
    let home = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let target = scratch.path().join("cache");
    let script = generated_script(home.path(), &target);
    let sourced = std::process::Command::new("bash")
        .env_remove("PIP_CACHE_DIR")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            "readonly PIP_CACHE_DIR=original; . \"$1\" && rm -f \"$1\"; status=$?; [ -e \"$1\" ] || exit 99; exit \"$status\"",
            "bash",
        ])
        .arg(&script)
        .output()
        .unwrap();
    assert!(!sourced.status.success());
    assert_ne!(sourced.status.code(), Some(99));
    assert!(script.exists());
}
