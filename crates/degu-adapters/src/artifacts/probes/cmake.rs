use super::{Probe, canonical_path, file_probe};
use degu_core::ecosystem::DetectCtx;
use std::path::{Path, PathBuf};

const HOME_PREFIX: &str = "CMAKE_HOME_DIRECTORY:INTERNAL=";

/// Cap on the CMakeCache.txt scan: 1 MiB covers a real cache while bounding
/// the allocation against huge or newline-free files.
const CACHE_READ_CAP: usize = 1024 * 1024;

pub(super) fn probe(path: &Path, ctx: &DetectCtx) -> Probe {
    let cache_file = file_probe(&path.join("CMakeCache.txt"), ctx);
    if cache_file != Probe::Match {
        return cache_file;
    }
    // In-source builds keep the cache beside source files, so the directory is not disposable.
    match file_probe(&path.join("CMakeLists.txt"), ctx) {
        Probe::Match => return Probe::Miss,
        Probe::Miss => {}
        outcome => return outcome,
    }

    let dir = match canonical_path(path, ctx) {
        Ok(dir) => dir,
        Err(outcome) => return outcome,
    };
    let home = match read_home(path, ctx) {
        Ok(Some(home)) => home,
        Ok(None) => return Probe::Miss,
        Err(outcome) => return outcome,
    };
    let home = match canonical_path(&home, ctx) {
        Ok(home) => home,
        Err(outcome) => return outcome,
    };
    if home == dir {
        Probe::Miss
    } else {
        Probe::Match
    }
}

fn read_home(path: &Path, ctx: &DetectCtx) -> Result<Option<PathBuf>, Probe> {
    if ctx.deadline_elapsed() {
        return Err(Probe::Truncated { incomplete: false });
    }
    let cache_path = path.join("CMakeCache.txt");
    // Safe primitive: a FIFO named CMakeCache.txt must not hang classification;
    // a non-regular cache carries no marker -> Incomplete, like the open-error path.
    let read = match degu_walk::read_regular_capped(&cache_path, CACHE_READ_CAP) {
        Ok(Some(read)) => read,
        Ok(None) => return Err(Probe::Incomplete),
        Err(err) => {
            tracing::warn!(path = %cache_path.display(), %err, "CMake cache open failed during artifact classification");
            return Err(Probe::Incomplete);
        }
    };
    let text = String::from_utf8_lossy(&read.bytes);
    let mut lines = text.lines();
    loop {
        if ctx.deadline_elapsed() {
            return Err(Probe::Truncated { incomplete: false });
        }
        let Some(line) = lines.next() else {
            // A cut-off tail could drop the marker line, so a truncated cache is
            // indeterminate rather than a clean miss.
            if read.truncated {
                tracing::warn!(path = %cache_path.display(), "CMake cache exceeds the read limit");
                return Err(Probe::Incomplete);
            }
            return Ok(None);
        };
        if let Some(home) = line
            .strip_prefix(HOME_PREFIX)
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(home.into()));
        }
    }
}
