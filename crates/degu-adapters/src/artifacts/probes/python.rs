use super::Probe;
use degu_core::ecosystem::DetectCtx;
use std::ffi::OsStr;
use std::path::Path;

pub(super) fn cache_root(path: &Path, ctx: &DetectCtx) -> Probe {
    if ctx.deadline_elapsed() {
        return Probe::Truncated { incomplete: false };
    }
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "python cache directory read failed during artifact classification");
            return Probe::Incomplete;
        }
    };
    let mut has_bytecode = false;
    for entry in entries {
        if ctx.deadline_elapsed() {
            return Probe::Truncated { incomplete: false };
        }
        match bytecode_entry(entry, path) {
            Probe::Match => has_bytecode = true,
            Probe::ReportOnly => return Probe::ReportOnly,
            Probe::Incomplete => return Probe::Incomplete,
            Probe::Miss | Probe::Truncated { .. } => {
                unreachable!("python cache entries return a definitive classification")
            }
        }
    }
    if has_bytecode {
        Probe::Match
    } else {
        Probe::ReportOnly
    }
}

fn bytecode_entry(entry: std::io::Result<std::fs::DirEntry>, root: &Path) -> Probe {
    let entry = match entry {
        Ok(entry) => entry,
        Err(error) => {
            tracing::warn!(path = %root.display(), %error, "python cache entry read failed during artifact classification");
            return Probe::Incomplete;
        }
    };
    let path = entry.path();
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "python cache entry type probe failed during artifact classification");
            return Probe::Incomplete;
        }
    };
    if file_type.is_file() && path.extension() == Some(OsStr::new("pyc")) {
        Probe::Match
    } else {
        Probe::ReportOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn context() -> DetectCtx {
        DetectCtx::from_process().unwrap()
    }

    #[test]
    fn empty_cache_is_report_only() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            cache_root(root.path(), &context()),
            Probe::ReportOnly
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bytecode_symlink_makes_cache_report_only() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"user-owned data").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("module.pyc")).unwrap();
        assert!(matches!(
            cache_root(root.path(), &context()),
            Probe::ReportOnly
        ));
    }

    #[test]
    fn elapsed_deadline_precedes_directory_read() {
        let ctx = context().with_deadline(Some(Instant::now()));
        assert!(matches!(
            cache_root(Path::new("/degu-missing/__pycache__"), &ctx),
            Probe::Truncated { .. }
        ));
    }
}
