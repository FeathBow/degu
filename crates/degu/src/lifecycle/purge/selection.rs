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
        .map(|path| Selector::new(path))
        .collect::<Result<Vec<_>>>()?;
    let records = OperationLog::new(ctx).read()?;
    let recorded = reconciled_trash_info(&records);
    let selects = |original: &Path| {
        let resolved = resolve_deepest_existing(original).ok();
        selection
            .iter()
            .any(|chosen| chosen.selects(original, resolved.as_deref()))
    };
    let plan = plan_matching_trash(ctx, |entry| {
        recorded
            .get(entry)
            .is_some_and(|info| selects(&info.original))
    })?;
    let planned = plan
        .entries()
        .filter_map(|entry| recorded.get(entry))
        .map(|info| info.original.clone())
        .collect::<Vec<_>>();
    let unmatched = selection
        .into_iter()
        .filter(|chosen| {
            !planned.iter().any(|origin| {
                chosen.selects(origin, resolve_deepest_existing(origin).ok().as_deref())
            })
        })
        .map(|chosen| chosen.absolute)
        .collect();
    Ok(SelectedTrashPlan { plan, unmatched })
}

/// Resolve as much of a path as still exists, leaving the rest lexical.
///
/// A purge names a location that has already been staged away, so resolving
/// the whole path would fail for the ordinary case. Resolving the deepest part
/// that survives still reaches through a symlinked ancestor and a `..`.
fn resolve_deepest_existing(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("failed to resolve {}", path.display()))?;
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

/// A selector in both spellings.
///
/// The operation log records the path the adapter produced, which still
/// carries whatever symlinks that path was spelled with — degu resolves the
/// home directory but not the cache directories beneath it. So a reader who
/// types the path degu printed needs the spelling compared as typed, and a
/// reader who reaches the same place another way needs it compared resolved.
/// Neither spelling alone matches every recorded origin.
struct Selector {
    absolute: PathBuf,
    resolved: PathBuf,
}

impl Selector {
    fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            absolute: std::path::absolute(path)
                .with_context(|| format!("failed to resolve --path {}", path.display()))?,
            resolved: resolve_deepest_existing(path)?,
        })
    }

    fn selects(&self, original: &Path, resolved_original: Option<&Path>) -> bool {
        original.starts_with(&self.absolute)
            || resolved_original.is_some_and(|origin| origin.starts_with(&self.resolved))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn selector(path: &Path) -> Selector {
        Selector::new(path).unwrap()
    }

    /// The operation log records the path the adapter produced. A cache
    /// directory reached through a symlink is recorded with the symlink in it,
    /// so the spelling a reader copies out of degu's own output has to match
    /// as typed.
    #[test]
    fn a_selector_matches_an_origin_recorded_through_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("scratch/caches");
        std::fs::create_dir_all(&real).unwrap();
        let alias = root.path().join("caches");
        symlink(&real, &alias).unwrap();
        let recorded = alias.join("go-build");

        let chosen = selector(&recorded);

        assert!(
            chosen.selects(
                &recorded,
                resolve_deepest_existing(&recorded).ok().as_deref()
            ),
            "the path degu printed did not match the origin it recorded"
        );
    }

    /// The same place reached the other way round: the origin is recorded
    /// resolved and the reader names it through the symlink.
    #[test]
    fn a_selector_through_a_symlink_matches_a_resolved_origin() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("scratch/caches");
        std::fs::create_dir_all(&real).unwrap();
        let alias = root.path().join("caches");
        symlink(&real, &alias).unwrap();
        let recorded = std::fs::canonicalize(&real).unwrap().join("go-build");

        let chosen = selector(&alias.join("go-build"));

        assert!(chosen.selects(
            &recorded,
            resolve_deepest_existing(&recorded).ok().as_deref()
        ));
    }

    #[test]
    fn a_selector_resolves_a_parent_component() {
        let root = std::fs::canonicalize(tempfile::tempdir().unwrap().path()).unwrap();
        std::fs::create_dir_all(root.join("caches")).unwrap();
        let recorded = root.join("caches/go-build");

        let chosen = selector(&root.join("caches/../caches/go-build"));

        assert!(chosen.selects(
            &recorded,
            resolve_deepest_existing(&recorded).ok().as_deref()
        ));
    }

    /// Matching is by whole path components, so a lexical neighbour is a
    /// different place. A string prefix would quietly widen every selection.
    #[test]
    fn a_selector_does_not_reach_a_sibling_sharing_its_name_prefix() {
        let root = std::fs::canonicalize(tempfile::tempdir().unwrap().path()).unwrap();
        let recorded = root.join("go-build");

        let chosen = selector(&root.join("go"));

        assert!(!chosen.selects(
            &recorded,
            resolve_deepest_existing(&recorded).ok().as_deref()
        ));
    }

    /// An origin staged away no longer exists, so only its surviving ancestors
    /// can resolve; the rest stays as spelled.
    #[test]
    fn resolution_keeps_the_part_that_no_longer_exists() {
        let root = std::fs::canonicalize(tempfile::tempdir().unwrap().path()).unwrap();

        let resolved = resolve_deepest_existing(&root.join("gone/deeper")).unwrap();

        assert_eq!(resolved, root.join("gone/deeper"));
    }
}
