use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;

use super::super::journal::OperationLog;
use super::super::reconcile::reconciled_trash_info;
use super::super::storage::trash_roots;
use super::super::trash::Trash;
use super::plan::{PlannedTrashEntry, PurgePlanBatch, TrashPurgePlan};

/// A selected purge plan, with the selectors that reached no staged origin.
/// Matching nothing is a legitimate outcome, and indistinguishable from a
/// mistyped path unless the command can say which selector found nothing.
pub(crate) struct SelectedTrashPlan {
    pub(crate) plan: TrashPurgePlan,
    pub(crate) unmatched: Vec<PathBuf>,
}

pub(crate) fn plan_selected_trash(
    ctx: &DetectCtx,
    selection: &[PathBuf],
) -> Result<SelectedTrashPlan> {
    let selection = selection
        .iter()
        .map(|path| resolve_origin_selector(path))
        .collect::<Result<Vec<_>>>()?;
    let records = OperationLog::new(ctx).read()?;
    let recorded = reconciled_trash_info(&records);
    let selects = |original: &Path| selection.iter().any(|chosen| original.starts_with(chosen));
    let plan = plan_matching_trash(ctx, |entry| {
        recorded
            .get(entry)
            .is_some_and(|info| selects(&info.original))
    })?;
    let planned = plan
        .entries()
        .filter_map(|entry| recorded.get(entry))
        .map(|info| info.original.as_path())
        .collect::<Vec<_>>();
    let unmatched = selection
        .iter()
        .filter(|chosen| !planned.iter().any(|origin| origin.starts_with(chosen)))
        .cloned()
        .collect();
    Ok(SelectedTrashPlan { plan, unmatched })
}

/// Bring a selector into the namespace the operation log records.
///
/// `clean --path` canonicalizes its selector because the location it names is
/// still there to resolve. A purge selector names a location that has already
/// been staged away, so resolving the whole path would fail for the ordinary
/// case. Resolving the deepest part that still exists reaches the same
/// namespace anyway: a symlinked ancestor and a `..` are resolved by the
/// filesystem, and only components that no longer exist stay lexical.
fn resolve_origin_selector(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("failed to resolve --path {}", path.display()))?;
    let mut unresolved = Vec::new();
    let mut probe = absolute.as_path();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(probe) {
            return Ok(unresolved
                .iter()
                .rev()
                .fold(resolved, |resolved, part| resolved.join(part)));
        }
        // A root has no parent, and a trailing `..` has no file name; neither
        // leaves anything further to resolve against.
        let (Some(parent), Some(name)) = (probe.parent(), probe.file_name()) else {
            return Ok(absolute);
        };
        unresolved.push(name.to_owned());
        probe = parent;
    }
}

pub(crate) fn plan_named_trash(ctx: &DetectCtx, entries: &[PathBuf]) -> Result<TrashPurgePlan> {
    let selected = entries
        .iter()
        .map(std::path::absolute)
        .collect::<std::io::Result<BTreeSet<_>>>()
        .context("failed to resolve selected trash entries")?;
    let plan = plan_matching_trash(ctx, |entry| selected.contains(entry))?;
    let matched = plan
        .entries()
        .map(Path::to_path_buf)
        .collect::<BTreeSet<_>>();
    if let Some(missing) = selected.difference(&matched).next() {
        anyhow::bail!(
            "selected trash entry is no longer available or is not a managed entry: {}",
            crate::presentation::escape_terminal_text(&missing.display().to_string())
        );
    }
    Ok(plan)
}

fn plan_matching_trash(
    ctx: &DetectCtx,
    includes: impl Fn(&Path) -> bool,
) -> Result<TrashPurgePlan> {
    let mut batches = Vec::new();
    for root in trash_roots(ctx)? {
        let entries = Trash::new(root.clone())
            .entries_matching(|entry, _| includes(entry))
            .with_context(|| format!("failed to select trash in {}", root.display()))?
            .into_iter()
            .map(PlannedTrashEntry::capture)
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("failed to snapshot trash in {}", root.display()))?;
        batches.push(PurgePlanBatch {
            trash_root: root,
            entries,
        });
    }
    Ok(TrashPurgePlan { batches })
}
