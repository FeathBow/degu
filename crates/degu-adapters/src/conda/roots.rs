use super::{ECOSYSTEM_ID, ROLE_ENVIRONMENT};
use degu_core::ecosystem::{DetectCtx, Root, RootOutcome, RootProvenance};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub(super) fn discover(ctx: &DetectCtx) -> RootOutcome {
    // Environments resolve first so their bases can nominate pkgs roots the fixed
    // HOME-relative list cannot see; truncation still drops the whole outcome
    // upstream, so the reordering stays externally invisible.
    let mut outcome = environment_roots(ctx);
    if outcome.truncated {
        return outcome;
    }
    let packages = package_roots(ctx, &outcome.roots);
    outcome.merge(packages);
    outcome
}

fn package_roots(ctx: &DetectCtx, environments: &[Root]) -> RootOutcome {
    // The redirect replaces every default location: when set, neither the
    // fixed list nor environment-derived bases contribute candidates.
    if let Some(dirs) = ctx.env("CONDA_PKGS_DIRS") {
        return crate::resolve_existing_roots(ctx, ECOSYSTEM_ID, package_redirects(dirs));
    }
    well_known_package_roots(ctx, environments)
}

/// Fixed-list pkgs roots plus environment-derived ones, converged by canonical
/// path so a base visible to both sources yields exactly one root.
fn well_known_package_roots(ctx: &DetectCtx, environments: &[Root]) -> RootOutcome {
    let mut outcome = crate::resolve_existing_roots(
        ctx,
        ECOSYSTEM_ID,
        distro_roots(ctx)
            .into_iter()
            .map(|root| Root::well_known(root.join("pkgs"))),
    );
    if outcome.truncated {
        return outcome;
    }
    let mut derived = derive_package_roots(ctx, environments);
    // Derived paths are canonical by construction; a fixed-list path may cross a
    // symlinked distro directory, so canonicalize it once to compare.
    for fixed in &outcome.roots {
        if derived.roots.is_empty() || derived.truncated {
            break;
        }
        if ctx.deadline_elapsed() {
            derived.mark_truncated();
            break;
        }
        match std::fs::canonicalize(&fixed.path) {
            Ok(canonical) => derived.roots.retain(|root| root.path != canonical),
            // A vanished fixed root cannot collide with a derived root that
            // was corroborated on disk moments ago.
            Err(error) if crate::is_missing_path_error(&error) => {}
            Err(error) => {
                // Fail closed: without the canonical form a derived root cannot be proven
                // distinct, and a duplicate root would count the same cache twice.
                tracing::warn!(path = %fixed.path.display(), %error, "conda package root canonicalize failed");
                derived.roots.clear();
                derived.incomplete = true;
            }
        }
    }
    outcome.merge(derived);
    outcome
}

/// Only WellKnown environments nominate: redirect-provenance environments
/// (CONDA_ENVS_PATH/DIRS) must not widen the well-known surface. A derived
/// root stays WellKnown -- a fixed ecosystem subdirectory beneath a standard
/// conda base -- and additionally demands the full marker triad to exist.
fn derive_package_roots(ctx: &DetectCtx, environments: &[Root]) -> RootOutcome {
    let mut outcome = RootOutcome::default();
    for environment in environments {
        if environment.provenance != RootProvenance::WellKnown {
            continue;
        }
        for base in nominated_bases(&environment.path) {
            if ctx.deadline_elapsed() {
                outcome.mark_truncated();
                return outcome;
            }
            let pkgs = base.join("pkgs");
            if outcome.roots.iter().any(|root| root.path == pkgs) {
                continue;
            }
            match corroborate_base(ctx, &base, &mut outcome.incomplete) {
                Corroboration::Corroborated => {
                    tracing::debug!(
                        base = %base.display(),
                        environment = %environment.path.display(),
                        markers = "conda-meta, pkgs, pkgs/urls.txt",
                        "conda package root derived from environment base"
                    );
                    outcome.roots.push(Root::well_known(pkgs));
                }
                Corroboration::Rejected(marker) => {
                    tracing::debug!(
                        base = %base.display(),
                        environment = %environment.path.display(),
                        marker,
                        "conda package root nomination not corroborated"
                    );
                }
                Corroboration::Truncated => {
                    outcome.mark_truncated();
                    return outcome;
                }
            }
        }
    }
    outcome
}

/// One environment nominates: itself (a root environment is its own base) and,
/// when it sits in an envs directory, the directory holding envs -- the only
/// two layouts conda creates. A standalone --prefix env derives nothing.
fn nominated_bases(environment: &Path) -> Vec<PathBuf> {
    let mut bases = vec![environment.to_path_buf()];
    if let Some(parent) = environment.parent()
        && parent.file_name() == Some(OsStr::new("envs"))
        && let Some(base) = parent.parent()
    {
        bases.push(base.to_path_buf());
    }
    bases
}

enum Corroboration {
    Corroborated,
    Rejected(&'static str),
    Truncated,
}

/// All three markers must corroborate or the nomination is discarded:
/// conda-meta/ proves a conda install, a non-symlink pkgs/ keeps the path
/// canonical, and pkgs/urls.txt proves conda's own cache machinery wrote it.
fn corroborate_base(ctx: &DetectCtx, base: &Path, incomplete: &mut bool) -> Corroboration {
    if ctx.deadline_elapsed() {
        return Corroboration::Truncated;
    }
    if !probe_directory(&base.join("conda-meta"), incomplete, "conda-meta") {
        return Corroboration::Rejected("conda-meta");
    }
    if ctx.deadline_elapsed() {
        return Corroboration::Truncated;
    }
    let pkgs = base.join("pkgs");
    if !probe_marker(&pkgs, incomplete, "conda pkgs", std::fs::FileType::is_dir) {
        return Corroboration::Rejected("pkgs");
    }
    if ctx.deadline_elapsed() {
        return Corroboration::Truncated;
    }
    if !probe_marker(
        &pkgs.join("urls.txt"),
        incomplete,
        "conda pkgs urls.txt",
        std::fs::FileType::is_file,
    ) {
        return Corroboration::Rejected("pkgs/urls.txt");
    }
    Corroboration::Corroborated
}

fn package_redirects(dirs: &OsStr) -> impl Iterator<Item = Root> + '_ {
    dirs.as_bytes()
        .split(|byte| *byte == b',')
        .map(<[u8]>::trim_ascii)
        .filter(|dir| !dir.is_empty())
        .map(|dir| Root::redirect("CONDA_PKGS_DIRS", PathBuf::from(OsStr::from_bytes(dir))))
}

fn distro_roots(ctx: &DetectCtx) -> Vec<PathBuf> {
    [
        "miniconda3",
        "anaconda3",
        "miniforge3",
        "mambaforge",
        "micromamba",
        ".conda",
    ]
    .map(|name| ctx.home.join(name))
    .into()
}

#[derive(Default)]
pub(super) struct EnvironmentRoots {
    pub(super) roots: Vec<Root>,
    incomplete: bool,
    truncated: bool,
}

impl EnvironmentRoots {
    pub(super) fn push(&mut self, ctx: &DetectCtx, mut root: Root) {
        if self.stop_at_deadline(ctx) {
            return;
        }
        if !crate::validate_root_path(ctx, ECOSYSTEM_ID, &root) {
            self.incomplete = true;
            return;
        }
        if !self.is_environment(ctx, &root.path) {
            return;
        }
        if self.stop_at_deadline(ctx) {
            return;
        }
        let canonical = match std::fs::canonicalize(&root.path) {
            Ok(path) => path,
            Err(error) if crate::is_missing_path_error(&error) => return,
            Err(error) => {
                tracing::warn!(path = %root.path.display(), %error, "conda environment canonicalize failed");
                self.incomplete = true;
                return;
            }
        };
        if let Some(existing) = self.roots.iter_mut().find(|root| root.path == canonical) {
            if root.provenance == RootProvenance::Redirect {
                existing.provenance = root.provenance;
                existing.origin = root.origin;
            }
            return;
        }
        root.path = canonical;
        root.role = Some(ROLE_ENVIRONMENT);
        self.roots.push(root);
    }

    fn is_environment(&mut self, ctx: &DetectCtx, path: &Path) -> bool {
        if self.stop_at_deadline(ctx) {
            return false;
        }
        if !probe_directory(path, &mut self.incomplete, "conda environment") {
            return false;
        }
        if self.stop_at_deadline(ctx) {
            return false;
        }
        probe_directory(&path.join("conda-meta"), &mut self.incomplete, "conda-meta")
    }

    fn push_children(&mut self, ctx: &DetectCtx, root: Root) {
        if self.stop_at_deadline(ctx) {
            return;
        }
        if !crate::validate_root_path(ctx, ECOSYSTEM_ID, &root) {
            self.incomplete = true;
            return;
        }
        if self.stop_at_deadline(ctx) {
            return;
        }
        let mut entries = match std::fs::read_dir(&root.path) {
            Ok(entries) => entries,
            Err(error) if crate::is_missing_path_error(&error) => return,
            Err(error) => {
                tracing::warn!(root = %root.path.display(), %error, "conda envs directory scan failed");
                self.incomplete = true;
                return;
            }
        };
        loop {
            if self.stop_at_deadline(ctx) {
                break;
            }
            let Some(entry) = entries.next() else {
                break;
            };
            match entry {
                Ok(entry) => self.push(
                    ctx,
                    Root {
                        path: entry.path(),
                        provenance: root.provenance,
                        origin: root.origin,
                        role: None,
                    },
                ),
                Err(error) => {
                    tracing::warn!(root = %root.path.display(), %error, "conda envs directory entry scan failed");
                    self.incomplete = true;
                }
            }
        }
    }

    fn stop_at_deadline(&mut self, ctx: &DetectCtx) -> bool {
        if !ctx.deadline_elapsed() {
            return false;
        }
        self.truncated = true;
        true
    }

    fn finish(mut self) -> RootOutcome {
        self.roots.sort_by(|left, right| left.path.cmp(&right.path));
        RootOutcome {
            roots: self.roots,
            incomplete: self.incomplete,
            truncated: self.truncated,
            ..RootOutcome::default()
        }
    }
}

fn environment_roots(ctx: &DetectCtx) -> RootOutcome {
    let mut envs = EnvironmentRoots::default();
    push_registered_environments(ctx, &mut envs);
    if envs.truncated {
        return envs.finish();
    }
    for root in distro_roots(ctx) {
        envs.push_children(ctx, Root::well_known(root.join("envs")));
        if envs.truncated {
            return envs.finish();
        }
    }

    if envs.stop_at_deadline(ctx) {
        return envs.finish();
    }
    let redirects = [
        ("CONDA_ENVS_PATH", ctx.env("CONDA_ENVS_PATH")),
        ("CONDA_ENVS_DIRS", ctx.env("CONDA_ENVS_DIRS")),
    ];
    if redirects.iter().all(|(_, paths)| paths.is_some()) {
        tracing::warn!("CONDA_ENVS_PATH and CONDA_ENVS_DIRS are both set");
        envs.incomplete = true;
    }
    for (variable, paths) in redirects {
        if let Some(paths) = paths {
            for root in std::env::split_paths(paths) {
                envs.push_children(ctx, Root::redirect(variable, root));
                if envs.truncated {
                    return envs.finish();
                }
            }
        }
    }
    envs.finish()
}

/// Cap on environments.txt (one path per line): 1 MiB fits thousands of
/// environments while bounding the allocation.
const ENVIRONMENTS_READ_CAP: usize = 1024 * 1024;

fn push_registered_environments(ctx: &DetectCtx, envs: &mut EnvironmentRoots) {
    if envs.stop_at_deadline(ctx) {
        return;
    }
    let path = ctx.home.join(".conda/environments.txt");
    // Safe primitive: a FIFO at environments.txt must not hang discovery and the
    // cap bounds the allocation; non-regular files are skipped like missing ones.
    let read = match degu_walk::read_regular_capped(&path, ENVIRONMENTS_READ_CAP) {
        Ok(Some(read)) => read,
        Ok(None) => return,
        Err(error) if crate::is_missing_path_error(&error) => return,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "conda environments.txt read failed");
            envs.incomplete = true;
            return;
        }
    };
    if read.truncated {
        tracing::warn!(path = %path.display(), "conda environments.txt exceeds the read limit");
        envs.incomplete = true;
    }
    // A cut-off tail is not a registry entry. Keep complete lines that preceded
    // the cap, but never trust the partial final line.
    let bytes = complete_registry_prefix(&read.bytes, read.truncated);
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.lines();
    loop {
        if envs.stop_at_deadline(ctx) {
            break;
        }
        let Some(line) = lines.next() else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let environment = PathBuf::from(line);
        if environment.is_absolute() {
            envs.push(ctx, Root::well_known(environment));
        } else {
            tracing::warn!(path = %environment.display(), "conda environment entry is not absolute");
            envs.incomplete = true;
        }
    }
}

fn complete_registry_prefix(bytes: &[u8], truncated: bool) -> &[u8] {
    if !truncated {
        return bytes;
    }
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

fn probe_directory(path: &Path, incomplete: &mut bool, label: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => true,
        Ok(_) => {
            tracing::debug!(path = %path.display(), "{label} candidate is not a directory");
            false
        }
        // A symlink loop is as determinate as a regular file: the entry can
        // never be a usable environment root, so it must not fail closed.
        Err(error)
            if crate::is_missing_path_error(&error)
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            tracing::debug!(path = %path.display(), %error, "{label} candidate is not a directory");
            false
        }
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "{label} root probe failed");
            *incomplete = true;
            false
        }
    }
}

/// Same three-way split as [probe_directory], but via symlink_metadata so a
/// symlinked marker can never corroborate -- derived roots must stay canonical
/// by construction.
fn probe_marker(
    path: &Path,
    incomplete: &mut bool,
    label: &str,
    corroborates: fn(&std::fs::FileType) -> bool,
) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if corroborates(&metadata.file_type()) => true,
        Ok(_) => {
            tracing::debug!(path = %path.display(), "{label} marker has the wrong file type");
            false
        }
        // Missing markers and symlink loops are as determinate as a wrong
        // file type: the base can never corroborate, so no fail-closed flag.
        Err(error)
            if crate::is_missing_path_error(&error)
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            tracing::debug!(path = %path.display(), %error, "{label} marker is absent");
            false
        }
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "{label} marker probe failed");
            *incomplete = true;
            false
        }
    }
}

#[cfg(test)]
mod tests;
