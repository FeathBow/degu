use std::os::unix::fs::PermissionsExt;

pub fn create(state: &tempfile::TempDir) -> std::path::PathBuf {
    let dir = state.path().join("degu");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
