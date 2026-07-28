use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use super::claims::CLAIMS_DIR_NAME;

pub(super) struct Trash {
    dir: PathBuf,
}

impl Trash {
    pub(super) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub(super) fn entries_matching(
        &self,
        should_purge: impl Fn(&Path, &std::fs::Metadata) -> bool,
    ) -> io::Result<Vec<PathBuf>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        let mut matching = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.file_name() == OsStr::new(CLAIMS_DIR_NAME) {
                continue;
            }
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if should_purge(&path, &meta) {
                matching.push(path);
            }
        }
        matching.sort();
        Ok(matching)
    }
}
