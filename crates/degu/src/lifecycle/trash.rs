use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

use degu_core::oplog::ObjectIdentity;

use super::claims::{CLAIMS_DIR_NAME, MAX_CLAIM_ATTEMPTS, prepare_claims_dir};

pub(in crate::lifecycle) mod removal;

pub(in crate::lifecycle) use removal::{ParentIdentityExpectation, parent_identity};

const SEQUENCE_WIDTH: usize = 4;

pub(super) struct Trash {
    dir: PathBuf,
}

impl Trash {
    pub(super) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub(super) fn reserve(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::create_dir_all(&self.dir)?;
        prepare_claims_dir(&self.dir)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
        let mut seq = self.next_seq()?;
        for _ in 0..MAX_CLAIM_ATTEMPTS {
            if let Some(entry) = self.try_reserve_sequence(seq, file_name)? {
                return Ok(entry);
            }
            seq = seq.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "trash sequence overflow")
            })?;
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "trash sequence claims exhausted",
        ))
    }

    fn try_reserve_sequence(&self, seq: u64, file_name: &OsStr) -> io::Result<Option<PathBuf>> {
        let entry = self.entry_path(seq, file_name);
        match std::fs::symlink_metadata(&entry) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "trash entry already exists",
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.claim_path_for_seq(seq))
        {
            Ok(_) => Ok(Some(entry)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub(super) fn release_reservation(&self, entry: &Path) -> io::Result<()> {
        let claim = self.claim_path_for_entry(entry)?;
        let metadata = match std::fs::symlink_metadata(&claim) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "trash reservation is not an empty regular file: {}",
                    claim.display()
                ),
            ));
        }
        removal::remove(&claim, ObjectIdentity::from_metadata(&metadata))
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

    pub(super) fn purge_entry_verified(
        &self,
        entry: &Path,
        expected: ObjectIdentity,
    ) -> io::Result<()> {
        if entry.parent() != Some(self.dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "purge entry is not a direct child of {}: {}",
                    self.dir.display(),
                    entry.display()
                ),
            ));
        }
        removal::remove(entry, expected)
    }

    fn claims_dir(&self) -> PathBuf {
        self.dir.join(CLAIMS_DIR_NAME)
    }

    fn claim_path_for_seq(&self, seq: u64) -> PathBuf {
        self.claims_dir().join(sequence_name(seq))
    }

    fn claim_path_for_entry(&self, entry: &Path) -> io::Result<PathBuf> {
        let seq = entry
            .file_name()
            .and_then(parse_seq)
            .map(sequence_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("trash entry has no sequence: {}", entry.display()),
                )
            })?;
        Ok(self.claims_dir().join(seq))
    }

    fn entry_path(&self, seq: u64, file_name: &OsStr) -> PathBuf {
        let mut entry_name = OsString::from(sequence_name(seq));
        entry_name.push("-");
        entry_name.push(file_name);
        self.dir.join(entry_name)
    }

    fn next_seq(&self) -> io::Result<u64> {
        let mut max = 0;
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.file_name() == OsStr::new(CLAIMS_DIR_NAME) {
                continue;
            }
            if let Some(seq) = parse_seq(&entry.file_name()) {
                max = max.max(seq);
            }
        }
        max.checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "trash sequence overflow"))
    }
}

fn sequence_name(seq: u64) -> String {
    format!("{seq:0width$}", width = SEQUENCE_WIDTH)
}

fn parse_seq(name: &OsStr) -> Option<u64> {
    let name = name.to_string_lossy();
    let (prefix, _) = name.split_once('-').unwrap_or((&name, ""));
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    prefix.parse().ok()
}

#[cfg(test)]
mod tests;
