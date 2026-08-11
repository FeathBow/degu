use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use degu_core::safety::Guard;
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const TRASHROOTS_FILE: &str = "degu/trashroots";
const TRASHROOTS_MAX_BYTES: usize = 1024 * 1024;
const TRASHROOT_RECORD_MAX_BYTES: usize = 64 * 1024;
const STATE_TRASH_NAME: &str = "trash";
const CROSS_DEVICE_TRASH_NAME: &str = ".degu-trash";
const SEALED_STAGING_STORE_NAME: &str = "sealed-staging";

#[cfg(test)]
mod tests;
mod validation;
pub(crate) use validation::ensure_managed_trash_root;
use validation::{ensure_state_parent, validate_existing_trash_root};

use super::journal::isolate_partial_tail;

pub(crate) fn trash_dir_state(ctx: &DetectCtx) -> PathBuf {
    ctx.xdg_state().join("degu/trash")
}

pub(crate) fn add_resolved_trash_roots_to_guard(
    ctx: &DetectCtx,
    findings: &[Finding],
    guard: &mut Guard,
) -> Result<()> {
    let mut seen = HashSet::new();
    for finding in findings {
        let root = resolve_trash_dir(ctx, finding.path()).map_err(|reason| {
            anyhow::anyhow!(
                "failed to resolve trash root for {} before guard check: {reason}",
                finding.path().display()
            )
        })?;
        if seen.insert(root.clone()) {
            guard.add(root)?;
        }
    }
    Ok(())
}

pub(crate) fn resolve_trash_dir(
    ctx: &DetectCtx,
    path: &Path,
) -> std::result::Result<PathBuf, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    let state_dir = ensure_state_dir(ctx).map_err(|err| {
        format!(
            "failed to prepare state dir {}: {err}",
            ctx.xdg_state().display()
        )
    })?;
    let state_meta = std::fs::symlink_metadata(&state_dir)
        .map_err(|err| format!("failed to inspect state dir {}: {err}", state_dir.display()))?;

    if meta.dev() == state_meta.dev() {
        return Ok(trash_dir_state(ctx));
    }

    let anchor = resolve_cross_device_anchor(path, meta.dev())?;
    Ok(anchor.join(".degu-trash"))
}

fn ensure_state_dir(ctx: &DetectCtx) -> std::io::Result<PathBuf> {
    let dir = ctx.xdg_state();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub(crate) fn sealed_staging_store_path(ctx: &DetectCtx) -> PathBuf {
    ctx.xdg_state().join("degu").join(SEALED_STAGING_STORE_NAME)
}

/// Existing recovery state is always authoritative and must be opened or block.
/// Returns `Some` on a certified-local backend — the caller then creates an
/// empty store on first mutation and reopens it thereafter — and `None` on an
/// uncertified backend (NFS/overlay-backed HPC state directories), where no
/// store is created and the strict legacy lifecycle is used so it does not
/// regress there before A3c4 enables forward sealed staging.
pub(crate) fn sealed_staging_store_for_mutation(
    ctx: &DetectCtx,
) -> Result<Option<(PathBuf, bool)>> {
    let lexical = sealed_staging_store_path(ctx);
    let lexical_parent = lexical.parent().ok_or_else(|| {
        anyhow::anyhow!("sealed-staging store has no parent: {}", lexical.display())
    })?;
    // SealWalStore rejects every symlink component. Resolve the already-created
    // state parent once, then let SealWalStore reopen and authenticate the
    // resulting absolute no-symlink chain descriptor by descriptor. This also
    // handles macOS's `/var -> /private/var` spelling.
    let parent = std::fs::canonicalize(lexical_parent).with_context(|| {
        format!(
            "failed to canonicalize sealed-staging store parent {}",
            lexical_parent.display()
        )
    })?;
    let path = parent.join(SEALED_STAGING_STORE_NAME);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => return Ok(Some((path, true))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect sealed-staging store {}", path.display())
            });
        }
    }

    let held_parent = std::fs::File::open(&parent).with_context(|| {
        format!(
            "failed to open sealed-staging store parent {}",
            parent.display()
        )
    })?;
    Ok(
        degu_core::local_backend::certify_held_fd_backend(&held_parent)
            .is_ok()
            .then_some((path, false)),
    )
}

pub(crate) fn acquire_mutation_lock(ctx: &DetectCtx) -> Result<std::fs::File> {
    let dir = ctx.xdg_state().join("degu");
    ensure_state_parent(&dir)?;
    let path = dir.join("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("failed to open mutation lock {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "another degu operation holds the mutation lock (a clean, undo, or purge is running); retry when it finishes"
        ),
        Err(std::fs::TryLockError::Error(err)) => {
            Err(err).with_context(|| format!("failed to lock mutation lock {}", path.display()))
        }
    }
}

fn resolve_cross_device_anchor(path: &Path, dev: u64) -> std::result::Result<PathBuf, String> {
    let euid = rustix::process::geteuid().as_raw();
    let mut current = path.parent().ok_or_else(|| {
        format!(
            "{} has no parent for cross-device trash anchor",
            path.display()
        )
    })?;
    let mut anchor = None;

    while let Ok(meta) = std::fs::symlink_metadata(current) {
        if !meta.is_dir()
            || meta.dev() != dev
            || meta.uid() != euid
            || rustix::fs::access(current, rustix::fs::Access::WRITE_OK).is_err()
        {
            break;
        }
        anchor = Some(current.to_path_buf());

        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent;
    }

    anchor.ok_or_else(|| {
        format!(
            "no writable owned same-device anchor found above {}",
            path.display()
        )
    })
}

pub(crate) fn register_trash_root(state_dir: &Path, root: &Path) -> Result<()> {
    if !is_registered_trash_root(root) {
        anyhow::bail!(
            "trash root {} must be absolute and end in {CROSS_DEVICE_TRASH_NAME}",
            root.display()
        );
    }
    let root_line = encode_trash_root(root)?;

    let registry = state_dir.join(TRASHROOTS_FILE);
    let registered = read_registered_trash_roots(&registry)?;
    if registered.iter().any(|registered| registered == root) {
        return Ok(());
    }

    if let Some(parent) = registry.parent() {
        ensure_state_parent(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(&registry)
        .with_context(|| format!("failed to open {}", registry.display()))?;
    isolate_partial_tail(&mut file)
        .with_context(|| format!("failed to inspect {}", registry.display()))?;
    writeln!(file, "{root_line}")
        .with_context(|| format!("failed to write {}", registry.display()))?;
    Ok(())
}

fn encode_trash_root(root: &Path) -> Result<String> {
    let encoded = root
        .to_str()
        .with_context(|| format!("trash root {} is not valid UTF-8", root.display()))?;
    serde_json::to_string(encoded).map_err(Into::into)
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
        super::records::StateReadLimits::new(TRASHROOTS_MAX_BYTES, TRASHROOT_RECORD_MAX_BYTES);
    super::records::visit_bounded_state_lines(registry, limits, |line_no, line| {
        let line = std::str::from_utf8(line).with_context(|| {
            format!(
                "failed to read {}: trash registry line {line_no} is not valid UTF-8",
                registry.display()
            )
        })?;
        roots.push(parse_registered_trash_root(line, registry, line_no)?);
        Ok(())
    })?;
    Ok(roots)
}

fn parse_registered_trash_root(line: &str, registry: &Path, line_no: usize) -> Result<PathBuf> {
    let (root, legacy) = match serde_json::from_str::<PathBuf>(line) {
        Ok(root) => (root, false),
        Err(_) => (PathBuf::from(line), true),
    };
    if !is_registered_trash_root(&root) {
        anyhow::bail!(
            "failed to read {}: corrupt trash registry line {line_no}",
            registry.display()
        );
    }
    if legacy {
        tracing::warn!(
            target: "degu",
            path = %registry.display(),
            line = line_no,
            "using legacy unquoted trash registry line"
        );
    }
    Ok(root)
}

fn is_registered_trash_root(root: &Path) -> bool {
    root.is_absolute() && root.file_name() == Some(std::ffi::OsStr::new(CROSS_DEVICE_TRASH_NAME))
}

fn trashroots_registry(ctx: &DetectCtx) -> PathBuf {
    ctx.xdg_state().join(TRASHROOTS_FILE)
}
