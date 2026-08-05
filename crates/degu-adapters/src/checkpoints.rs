use degu_core::ecosystem::{DetectCtx, ScanOutcome};
use degu_core::finding::{FindingCandidate, FindingKind, Ownership, Recovery};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CHECKPOINT_EXTENSIONS: [&str; 4] = ["ckpt", "pt", "pth", "safetensors"];
pub const SOURCE_ID: &str = "checkpoints";

pub(crate) fn named_checkpoint_finding(path: &Path, ctx: &DetectCtx) -> ScanOutcome {
    if ctx.deadline_elapsed() {
        return ScanOutcome::truncated();
    }
    let stats = match degu_walk::measure(path, &crate::walk_options(ctx)) {
        Ok(stats) => stats,
        Err(err) if crate::is_missing_path_error(&err) => {
            tracing::debug!(path = %path.display(), %err, "checkpoint root vanished during scan");
            return ScanOutcome::default();
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "checkpoint scan failed");
            return ScanOutcome::failed();
        }
    };
    crate::log_skipped_samples(SOURCE_ID, &stats);
    ScanOutcome::from_candidates(vec![checkpoint_candidate(
        path,
        &stats,
        CheckpointContents::Directory,
    )])
}

pub(crate) fn loose_checkpoint_finding(
    dir: &Path,
    files: &[PathBuf],
    ctx: &DetectCtx,
) -> ScanOutcome {
    let measured = measure_checkpoint_files(files, ctx);
    // A candidate here would claim zero checkpoint files in its rationale;
    // every file vanishing is a complete empty result, not a failure.
    if measured.files == 0 {
        let mut outcome = if measured.stats.truncated {
            ScanOutcome::truncated()
        } else {
            ScanOutcome::default()
        };
        if measured.incomplete {
            outcome.mark_incomplete_at(dir);
        }
        return outcome;
    }

    let exts = measured.extensions.into_iter().collect::<Vec<_>>();
    let mut outcome = ScanOutcome::from_candidates(vec![checkpoint_candidate(
        dir,
        &measured.stats,
        CheckpointContents::Loose {
            files: measured.files,
            extensions: exts.join(", "),
        },
    )]);
    if measured.incomplete {
        outcome.mark_incomplete_at(dir);
    }
    outcome
}

struct MeasuredCheckpoints {
    stats: degu_walk::WalkStats,
    incomplete: bool,
    files: usize,
    extensions: BTreeSet<String>,
}

fn measure_checkpoint_files(files: &[PathBuf], ctx: &DetectCtx) -> MeasuredCheckpoints {
    let opts = crate::walk_options(ctx);
    let mut measured = MeasuredCheckpoints {
        stats: degu_walk::WalkStats::default(),
        incomplete: false,
        files: 0,
        extensions: BTreeSet::new(),
    };
    for file in files {
        if ctx.deadline_elapsed() {
            measured.stats.truncated = true;
            break;
        }
        match degu_walk::measure(file, &opts) {
            Ok(file_stats) => {
                crate::log_skipped_samples(SOURCE_ID, &file_stats);
                measured.stats.merge(file_stats);
                measured.files = measured.files.saturating_add(1);
                if let Some(extension) = checkpoint_extension(file) {
                    measured.extensions.insert(extension);
                }
            }
            Err(err) if crate::is_missing_path_error(&err) => {
                tracing::debug!(path = %file.display(), %err, "checkpoint file vanished during scan");
            }
            Err(err) => {
                tracing::warn!(path = %file.display(), %err, "checkpoint file scan failed");
                measured.incomplete = true;
            }
        }
    }
    measured
}

enum CheckpointContents {
    Directory,
    Loose { files: usize, extensions: String },
}

fn checkpoint_candidate(
    path: &Path,
    stats: &degu_walk::WalkStats,
    contents: CheckpointContents,
) -> FindingCandidate {
    let age_days = crate::age_days(stats.newest_mtime);
    let rationale = match contents {
        CheckpointContents::Directory => format!(
            "checkpoints directory with {} files, newest {}; degu never deletes training output",
            stats.files,
            age_phrase(age_days)
        ),
        CheckpointContents::Loose { files, extensions } => format!(
            "{files} checkpoint files ({extensions}) in this directory (size counts the checkpoint files only, not the directory), newest {}; degu never deletes training output",
            age_phrase(age_days)
        ),
    };
    FindingCandidate {
        ecosystem: SOURCE_ID.to_string(),
        path: path.to_path_buf(),
        kind: FindingKind::Checkpoint,
        bytes_apparent: stats.bytes_apparent,
        bytes_allocated: stats.bytes_allocated,
        age_days,
        bytes_hardlinked: stats.bytes_hardlinked,
        inodes: stats.inodes,
        skipped: stats.skipped_total,
        truncated: stats.truncated,
        unvisited_dirs: stats.unvisited_dirs,
        shared_writable_dirs: stats.shared_writable_dirs,
        parent_grants_foreign_mutation: false,
        protected_boundaries: stats.excluded_entries,
        protected_credential_boundaries: stats.excluded_credential_boundaries,
        recovery: Recovery::UserAsset,
        ownership: Ownership::Standalone,
        hazard: None,
        rationale,
    }
}

fn checkpoint_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| format!(".{}", extension.to_ascii_lowercase()))
}

fn age_phrase(age_days: Option<u64>) -> String {
    age_days
        .map(|days| format!("{days} days old"))
        .unwrap_or_else(|| "unknown age".to_string())
}

pub(crate) fn is_named_checkpoint_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "checkpoint" | "checkpoints"))
}

pub(crate) fn is_checkpoint_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            CHECKPOINT_EXTENSIONS
                .iter()
                .any(|checkpoint_ext| ext.eq_ignore_ascii_case(checkpoint_ext))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_checkpoint_files_vanishing_is_a_complete_empty_result() {
        let ctx = DetectCtx::from_process().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let files = [dir.path().join("a.ckpt"), dir.path().join("b.pt")];

        let outcome = loose_checkpoint_finding(dir.path(), &files, &ctx);

        assert!(outcome.candidates.is_empty());
        assert!(!outcome.incomplete);
        assert!(!outcome.truncated);
    }
}
