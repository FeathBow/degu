use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;

use super::super::journal::OperationLog;
use super::super::reconcile::reconciled_trash_info;
use super::super::storage::trash_roots;
use super::super::trash::Trash;
use super::plan::{PlannedTrashEntry, PurgePlanBatch, TrashPurgePlan};

pub(crate) fn plan_selected_trash(
    ctx: &DetectCtx,
    selection: &[PathBuf],
) -> Result<TrashPurgePlan> {
    let records = OperationLog::new(ctx).read()?;
    let recorded = reconciled_trash_info(&records);
    plan_matching_trash(ctx, |entry| {
        recorded.get(entry).is_some_and(|info| {
            selection
                .iter()
                .any(|chosen| info.original.starts_with(chosen))
        })
    })
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
