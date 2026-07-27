use std::path::{Path, PathBuf};

pub(super) fn create_count_fixture(root: &Path) {
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    for index in 0..3 {
        std::fs::write(first.join(format!("file-{index}.bin")), [index as u8]).unwrap();
    }
    for index in 0..4 {
        std::fs::write(second.join(format!("file-{index}.bin")), [index as u8]).unwrap();
    }
}

pub(super) fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|uid| uid.trim() == "0")
}

pub(super) fn restore_readable(paths: &[PathBuf]) {
    use std::os::unix::fs::PermissionsExt;

    for path in paths {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
}
