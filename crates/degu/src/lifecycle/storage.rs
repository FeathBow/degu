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
#[cfg(test)]
use validation::ensure_managed_trash_root_with_sync;
use validation::{ensure_state_parent, validate_existing_trash_root};

use super::journal::isolate_partial_tail;

pub(crate) fn trash_dir_state(ctx: &DetectCtx) -> PathBuf {
    ctx.xdg_state().join("degu/trash")
}

pub(crate) fn is_state_trash_root(ctx: &DetectCtx, root: &Path) -> bool {
    let canonical_root = root
        .parent()
        .zip(root.file_name())
        .and_then(|(parent, name)| {
            std::fs::canonicalize(parent)
                .ok()
                .map(|parent| parent.join(name))
        });
    std::fs::canonicalize(ctx.xdg_state())
        .map(|state| Some(state.join("degu/trash")) == canonical_root)
        .unwrap_or_else(|_| trash_dir_state(ctx) == root)
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
    let canonical = std::fs::canonicalize(path)
        .map_err(|err| format!("failed to canonicalize {}: {err}", path.display()))?;
    let source_mount = path_mount_id(&canonical)?;
    let mount_owner_anchor = resolve_mount_owner_anchor(&canonical, source_mount)?;
    let state_dir = ensure_state_dir(ctx).map_err(|err| {
        format!(
            "failed to prepare state dir {}: {err}",
            ctx.xdg_state().display()
        )
    })?;
    let state_dir = std::fs::canonicalize(&state_dir).map_err(|err| {
        format!(
            "failed to canonicalize state dir {}: {err}",
            state_dir.display()
        )
    })?;
    let state_mount = path_mount_id(&state_dir)?;

    if source_mount == state_mount && state_dir.starts_with(&mount_owner_anchor) {
        return Ok(trash_dir_state(ctx));
    }

    Ok(mount_owner_anchor.join(".degu-trash"))
}

fn ensure_state_dir(ctx: &DetectCtx) -> std::io::Result<PathBuf> {
    let dir = ctx.xdg_state();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub(crate) fn sealed_staging_store_path(ctx: &DetectCtx) -> PathBuf {
    ctx.xdg_state().join("degu").join(SEALED_STAGING_STORE_NAME)
}

/// Discover the whole-store authority from the fixed current-EUID anchor, or
/// durably activate the current state-store locator. Once activated, the
/// recorded locator wins over XDG drift and is opened without recreation. Only
/// an authenticated, record-empty anchor whose desired store backend is
/// explicitly unsupported may keep the strict legacy lifecycle dormant.
pub(crate) fn sealed_staging_store_for_mutation(
    ctx: &DetectCtx,
) -> Result<degu_core::activation::MutationStoreActivation> {
    sealed_staging_store_for_mutation_with(ctx, degu_core::activation::activate_current_euid_store)
}

pub(super) fn sealed_staging_store_for_mutation_with<F>(
    ctx: &DetectCtx,
    activate: F,
) -> Result<degu_core::activation::MutationStoreActivation>
where
    F: FnOnce(
        &Path,
    ) -> std::result::Result<
        degu_core::activation::MutationStoreActivation,
        degu_core::activation::StoreActivationError,
    >,
{
    let lexical = sealed_staging_store_path(ctx);
    let lexical_parent = lexical.parent().ok_or_else(|| {
        anyhow::anyhow!("sealed-staging store has no parent: {}", lexical.display())
    })?;
    // Resolve the already-created platform spelling once (notably macOS
    // `/var -> /private/var`); core reopens every resulting component no-follow.
    let parent = std::fs::canonicalize(lexical_parent).with_context(|| {
        format!(
            "failed to canonicalize sealed-staging store parent {}",
            lexical_parent.display()
        )
    })?;
    let desired = parent.join(SEALED_STAGING_STORE_NAME);

    activate(&desired)
        .context("failed to discover or activate the current account sealed-staging store")
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

pub(crate) fn path_mount_id(path: &Path) -> std::result::Result<u64, String> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        format!(
            "failed to open mount identity path {}: {error}",
            path.display()
        )
    })?;
    degu_core::sealed_staging::forward_mount_id(&fd).map_err(|error| {
        format!(
            "failed to inspect mount identity at {}: {error}",
            path.display()
        )
    })
}

pub(crate) fn resolve_mount_owner_anchor(
    path: &Path,
    mount_id: u64,
) -> std::result::Result<PathBuf, String> {
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
            || path_mount_id(current)? != mount_id
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
    register_trash_root_with_sync(state_dir, root, |path| {
        std::fs::File::open(path)?.sync_all()
    })
}

fn register_trash_root_with_sync<F>(state_dir: &Path, root: &Path, mut sync: F) -> Result<()>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    if !is_registered_trash_root(root) {
        anyhow::bail!(
            "trash root {} must be absolute and end in {CROSS_DEVICE_TRASH_NAME}",
            root.display()
        );
    }
    let root_line = encode_trash_root(root)?;

    let registry = state_dir.join(TRASHROOTS_FILE);
    let registered = read_registered_trash_roots(&registry)?;
    let already_registered = registered.iter().any(|registered| registered == root);

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
    if !already_registered {
        writeln!(file, "{root_line}")
            .with_context(|| format!("failed to write {}", registry.display()))?;
    }
    file.flush()
        .with_context(|| format!("failed to flush {}", registry.display()))?;
    sync(&registry).with_context(|| format!("failed to sync {}", registry.display()))?;
    let parent = registry
        .parent()
        .ok_or_else(|| anyhow::anyhow!("trash registry has no parent: {}", registry.display()))?;
    sync(parent)
        .with_context(|| format!("failed to sync trash registry parent {}", parent.display()))?;
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
