use anyhow::{Context, Result};
use std::path::Path;

#[derive(Clone, Copy)]
pub(super) struct StateReadLimits {
    total_bytes: usize,
    line_bytes: usize,
}

impl StateReadLimits {
    pub(super) const fn new(total_bytes: usize, line_bytes: usize) -> Self {
        Self {
            total_bytes,
            line_bytes,
        }
    }
}

pub(super) fn visit_bounded_state_lines(
    path: &Path,
    limits: StateReadLimits,
    mut visit: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<()> {
    let read = match degu_walk::read_regular_capped(path, limits.total_bytes) {
        Ok(Some(read)) => read,
        Ok(None) => anyhow::bail!("failed to read {}: not a regular file", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    if read.truncated {
        anyhow::bail!(
            "failed to read {}: exceeds the {}-byte state-file limit",
            path.display(),
            limits.total_bytes
        );
    }
    for (index, raw_line) in read
        .bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
    {
        let line = strip_line_ending(raw_line);
        if line.len() > limits.line_bytes {
            anyhow::bail!(
                "failed to read {}: line {} exceeds the {}-byte record limit",
                path.display(),
                index + 1,
                limits.line_bytes
            );
        }
        visit(index + 1, line)?;
    }
    Ok(())
}

fn strip_line_ending(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

#[cfg(test)]
mod tests;
