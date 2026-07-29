use std::path::{Path, PathBuf};

pub fn visible(trash_dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(trash_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != ".claims")
        .collect()
}
