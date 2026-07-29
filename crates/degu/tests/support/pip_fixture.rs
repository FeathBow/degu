pub fn create() -> (tempfile::TempDir, tempfile::TempDir, std::path::PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = crate::pip_cache::seed(home.path());
    (home, state, cache)
}
