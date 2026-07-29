use super::fenced_blocks;

const INSTALLATION: &str = include_str!("../../../../docs/installation.md");

#[cfg(unix)]
#[test]
fn manual_install_stops_after_checksum_failure() {
    let script = fenced_blocks(INSTALLATION, "sh")
        .into_iter()
        .find(|block| block.contains("sha256sum -c") && block.contains("install.sh"))
        .expect("missing manual archive installation script");
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::os::unix::fs::symlink("/usr/bin/true", bin.join("curl")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/false", bin.join("sha256sum")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/true", bin.join("tar")).unwrap();
    let harness_path = home.path().join("manual-install.sh");
    std::fs::write(&harness_path, script).unwrap();

    let output = std::process::Command::new("sh")
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .arg(&harness_path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!home.path().join(".local/bin").exists());
}
