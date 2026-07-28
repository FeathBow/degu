use degu_core::ecosystem::DetectCtx;
use std::path::Path;

const SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";
const LINE_LIMIT: usize = SIGNATURE.len() + 2;

/// Incomplete: tag state undeterminable (I/O error); Truncated: the deadline
/// elapsed before the probe finished.
#[derive(Clone, Copy, Debug)]
pub enum Probe {
    Match,
    Miss,
    Incomplete,
    Truncated,
}

/// Deadline-aware probe for scheduling decisions. The result orders work only;
/// cleanup authority re-checks the tag after scanning.
pub fn probe_for_scheduling(path: &Path, ctx: &DetectCtx) -> Probe {
    probe(path, Some(ctx))
}

pub(crate) fn probe(path: &Path, ctx: Option<&DetectCtx>) -> Probe {
    if ctx.is_some_and(DetectCtx::deadline_elapsed) {
        return Probe::Truncated;
    }
    // virtualenv writes CACHEDIR.TAG inside venvs, and a venv is not pure cache.
    let venv = path.join("pyvenv.cfg");
    match std::fs::metadata(&venv) {
        Ok(metadata) if metadata.is_file() => Probe::Miss,
        Ok(_) => probe_tag(path, ctx),
        Err(err) if crate::is_missing_path_error(&err) => probe_tag(path, ctx),
        Err(err) => {
            tracing::warn!(path = %venv.display(), %err, "pyvenv.cfg probe failed during cache-tag classification");
            Probe::Incomplete
        }
    }
}

fn probe_tag(path: &Path, ctx: Option<&DetectCtx>) -> Probe {
    if ctx.is_some_and(DetectCtx::deadline_elapsed) {
        return Probe::Truncated;
    }
    let tag = path.join("CACHEDIR.TAG");
    // Only the signature prefix is needed: cap the read and use the safe primitive
    // so a FIFO cannot hang the scan; a non-regular tag can never match (Miss).
    let prefix = match degu_walk::read_regular_capped(&tag, LINE_LIMIT) {
        Ok(Some(read)) => read.bytes,
        Ok(None) => return Probe::Miss,
        Err(err) if crate::is_missing_path_error(&err) => return Probe::Miss,
        Err(err) => {
            tracing::warn!(path = %tag.display(), %err, "CACHEDIR.TAG read failed during cache-tag classification");
            return Probe::Incomplete;
        }
    };
    if ctx.is_some_and(DetectCtx::deadline_elapsed) {
        return Probe::Truncated;
    }
    let first_line = prefix
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let first_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);
    if first_line == SIGNATURE.as_bytes() {
        Probe::Match
    } else {
        Probe::Miss
    }
}

pub fn has_valid_cachedir_tag(path: &Path) -> bool {
    matches!(probe(path, None), Probe::Match)
}
