use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const TRASHROOTS_FILE: &str = "degu/trashroots";
const TRASHROOTS_MAX_BYTES: usize = 1024 * 1024;
const TRASHROOT_RECORD_MAX_BYTES: usize = 64 * 1024;
const STATE_TRASH_NAME: &str = "trash";
const CROSS_DEVICE_TRASH_NAME: &str = ".degu-trash";

mod validation;
use validation::validate_existing_trash_root;

pub(crate) fn trash_dir_state(ctx: &DetectCtx) -> PathBuf {
    ctx.xdg_state().join("degu/trash")
}

pub(crate) fn trash_roots(ctx: &DetectCtx) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    let state = trash_dir_state(ctx);
    match validate_existing_trash_root(&state, STATE_TRASH_NAME)? {
        Some(root) => {
            seen.insert(root.canonical);
            roots.push(root.lexical);
        }
        None => {
            // A never-created state root cannot alias another; keep its lexical
            // path so enumeration still probes the expected location.
            roots.push(state);
        }
    }

    for root in read_registered_trash_roots(&trashroots_registry(ctx))? {
        match validate_existing_trash_root(&root, CROSS_DEVICE_TRASH_NAME)? {
            Some(validated) => {
                if seen.insert(validated.canonical) {
                    roots.push(validated.lexical);
                }
            }
            None => tracing::warn!(
                target: "degu",
                root = %root.display(),
                "registered trash root no longer exists"
            ),
        }
    }

    Ok(roots)
}

fn read_registered_trash_roots(registry: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    let limits =
        super::state_read::StateReadLimits::new(TRASHROOTS_MAX_BYTES, TRASHROOT_RECORD_MAX_BYTES);
    super::state_read::visit_bounded_state_lines(registry, limits, |line_no, line| {
        let line = match std::str::from_utf8(line) {
            Ok(line) => line,
            Err(_) => {
                tracing::warn!(
                    target: "degu",
                    path = %registry.display(),
                    line = line_no,
                    "skipping non-UTF-8 trash registry line"
                );
                return Ok(());
            }
        };
        if let Some(root) = parse_registered_trash_root(line, registry, line_no) {
            roots.push(root);
        }
        Ok(())
    })?;
    Ok(roots)
}

fn parse_registered_trash_root(line: &str, registry: &Path, line_no: usize) -> Option<PathBuf> {
    let (root, legacy) = match serde_json::from_str::<PathBuf>(line) {
        Ok(root) => (root, false),
        Err(_) => (PathBuf::from(line), true),
    };
    if !is_registered_trash_root(&root) {
        tracing::warn!(
            target: "degu",
            path = %registry.display(),
            line = line_no,
            "skipping corrupt trash registry line"
        );
        return None;
    }
    if legacy {
        tracing::warn!(
            target: "degu",
            path = %registry.display(),
            line = line_no,
            "using legacy unquoted trash registry line"
        );
    }
    Some(root)
}

fn is_registered_trash_root(root: &Path) -> bool {
    root.is_absolute() && root.file_name() == Some(std::ffi::OsStr::new(CROSS_DEVICE_TRASH_NAME))
}

fn trashroots_registry(ctx: &DetectCtx) -> PathBuf {
    ctx.xdg_state().join(TRASHROOTS_FILE)
}
