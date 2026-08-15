use anyhow::{Context, Result};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use serde::Serialize;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

const CACHEDIR_TAG: &str = "CACHEDIR.TAG";
const TAG_CONTENT: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55\n";
const SHARED_WRITE_MASK: rustix::fs::RawMode = 0o022;
const PERMISSION_MASK: rustix::fs::RawMode = 0o777;
const PRIVATE_UMASK: Mode = Mode::from_raw_mode(0o077);
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// Minimal, reachable `--init --json` shape: the two lists of exact cache-root
/// paths this run created and found already initialized. There is no `failed`
/// list (an initialization failure returns an error and prints no JSON) and no
/// per-entry state (the list an entry lands in already names its state).
#[derive(Serialize)]
pub(super) struct InitializationReport {
    initialized: Vec<String>,
    already_initialized: Vec<String>,
}

struct PlannedRoot {
    relative: PathBuf,
    path: PathBuf,
}

#[derive(Clone, Copy)]
enum PlannedState {
    Create,
    AlreadyInitialized,
}

struct Base {
    fd: OwnedFd,
    identity: Identity,
    existed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CreatedKind {
    Directory,
    File,
}

#[derive(Clone, Copy)]
struct Identity {
    device: libc::dev_t,
    inode: libc::ino_t,
    kind: CreatedKind,
}

struct CreatedEntry {
    parent: OwnedFd,
    name: OsString,
    path: PathBuf,
    kind: CreatedKind,
    identity: Option<Identity>,
}

struct UmaskRestore(Mode);

#[derive(Default)]
struct Transaction {
    created: Vec<CreatedEntry>,
}

pub(super) fn initialize(target: &Path, subdirs: &[PathBuf]) -> Result<InitializationReport> {
    initialize_with_hook(target, subdirs, &mut |_, _| Ok(()))
}

fn initialize_with_hook(
    target: &Path,
    subdirs: &[PathBuf],
    after_root: &mut dyn FnMut(usize, &Path) -> Result<()>,
) -> Result<InitializationReport> {
    let roots = validate_subdirs(target, subdirs)?;
    let mut transaction = Transaction::default();
    let outcome = run_transaction(target, roots, &mut transaction, after_root).and_then(
        |(report, base_identity)| {
            revalidate_target_binding(target, base_identity)?;
            Ok(report)
        },
    );
    match outcome {
        Ok(report) => Ok(report),
        Err(error) => match transaction.rollback() {
            Ok(()) => Err(error.context(
                "relocate initialization failed; creations from this run were rolled back",
            )),
            Err(residue) => Err(error.context(format!(
                "relocate initialization failed and rollback left residue: {}",
                residue.join(", ")
            ))),
        },
    }
}

/// Obtain the trusted base directory, plan the roots against it, and initialize
/// them. Returns the report and the base directory identity so the caller can
/// confirm the target binding is unchanged before printing exports.
fn run_transaction(
    target: &Path,
    roots: Vec<(PathBuf, PathBuf)>,
    transaction: &mut Transaction,
    after_root: &mut dyn FnMut(usize, &Path) -> Result<()>,
) -> Result<(InitializationReport, Identity)> {
    let base = obtain_base(target, transaction)?;
    let planned = if base.existed {
        preflight_roots(&base.fd, roots)?
    } else {
        roots
            .into_iter()
            .map(|(relative, path)| PlannedRoot { relative, path })
            .collect()
    };
    let report = execute_roots(&base.fd, planned, transaction, after_root)?;
    Ok((report, base.identity))
}

fn validate_subdirs(target: &Path, subdirs: &[PathBuf]) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut seen = BTreeSet::new();
    let mut roots = Vec::new();
    for subdir in subdirs {
        let mut component_count = 0;
        for component in subdir.components() {
            component_count += 1;
            if !matches!(component, Component::Normal(_)) {
                anyhow::bail!(
                    "relocation subdirectory {} must contain only normal relative path components",
                    subdir.display()
                );
            }
        }
        if component_count == 0 {
            anyhow::bail!("relocation subdirectory must not be empty");
        }
        let path = target.join(subdir);
        if seen.insert(path.clone()) {
            roots.push((subdir.clone(), path));
        }
    }
    Ok(roots)
}

/// Resolve the target's parent through a full trusted-namespace walk and return
/// the pinned parent descriptor, its path, and the target's final component.
///
/// Every directory the resolution touches — each lexical ancestor and each
/// directory a followed symlink resolves through — must grant no foreign mutation
/// authority (see [`require_trusted_namespace`]), so no foreign principal can
/// rename a component or re-point a symlink to redirect the target after the
/// fact. A symlink is followed only when it lives in such a namespace and is
/// itself owned by the effective user or root, and its target chain is validated
/// the same way. This admits root-managed system links (`/var`, `/tmp`) and
/// admin- or user-managed scratch links while refusing anything reachable
/// through a group-writable, non-sticky namespace.
fn open_trusted_parent(target: &Path) -> Result<(OwnedFd, PathBuf, OsString)> {
    let name = target.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "relocate target {} has no final path component",
            target.display()
        )
    })?;
    let parent_path = target.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "relocate target {} has no parent directory",
            target.display()
        )
    })?;
    let parent = degu_walk::resolve_trusted_directory(parent_path, "relocate target ancestor")?;
    Ok((parent, parent_path.to_path_buf(), name.to_os_string()))
}

/// Open (existing) or create (missing) the target directory through its
/// trust-validated parent. [`open_trusted_parent`] has already required every
/// ancestor to be a trusted namespace, so both an existing private target under
/// a group-writable ancestor and a to-be-created one are refused identically.
fn obtain_base(target: &Path, transaction: &mut Transaction) -> Result<Base> {
    let (parent, _parent_path, name) = open_trusted_parent(target)?;
    match stat_at(&parent, name.as_os_str()) {
        Ok(stat) => {
            require_kind(&stat, CreatedKind::Directory, target, "relocate target")?;
            let fd = open_directory_at(&parent, name.as_os_str(), target)?;
            let opened = stat_fd(&fd, target)?;
            require_same_identity(&stat, &opened, target)?;
            require_existing_directory(&opened, target, "relocate target")?;
            Ok(Base {
                identity: identity(&opened, CreatedKind::Directory),
                fd,
                existed: true,
            })
        }
        Err(error) if error == rustix::io::Errno::NOENT => {
            let (fd, created) = create_directory(&parent, name.as_os_str(), target, transaction)?;
            let stat = stat_fd(&fd, target)?;
            if !created {
                require_existing_directory(&stat, target, "relocate target")?;
            }
            Ok(Base {
                identity: identity(&stat, CreatedKind::Directory),
                fd,
                existed: !created,
            })
        }
        Err(error) => Err(fs_error("inspect relocate target", target, error)),
    }
}

/// Re-resolve the target through the same no-follow walk and confirm it still
/// names the initialized directory before any export is printed. A group member
/// who renamed our private target and dropped a replacement in its place would
/// otherwise receive exports pointing at the replacement.
fn revalidate_target_binding(target: &Path, expected: Identity) -> Result<()> {
    let (parent, _parent_path, name) = open_trusted_parent(target)?;
    let stat = stat_at(&parent, name.as_os_str())
        .map_err(|error| fs_error("revalidate relocate target", target, error))?;
    require_kind(&stat, CreatedKind::Directory, target, "relocate target")?;
    let current = identity(&stat, CreatedKind::Directory);
    if current.device != expected.device || current.inode != expected.inode {
        anyhow::bail!(
            "relocate target {} no longer names the directory this run initialized; refusing to print exports",
            target.display()
        );
    }
    Ok(())
}

fn preflight_roots(base: &OwnedFd, roots: Vec<(PathBuf, PathBuf)>) -> Result<Vec<PlannedRoot>> {
    let mut deduplicated = BTreeSet::new();
    let mut planned = Vec::new();
    for (relative, path) in roots {
        let state = inspect_root(base, &relative, &path)?;
        let key = match state {
            PlannedState::Create => path.clone(),
            PlannedState::AlreadyInitialized => {
                std::fs::canonicalize(&path).with_context(|| {
                    format!("canonicalize initialized cache root {}", path.display())
                })?
            }
        };
        if deduplicated.insert(key) {
            planned.push(PlannedRoot { relative, path });
        }
    }
    Ok(planned)
}

fn inspect_root(base: &OwnedFd, relative: &Path, path: &Path) -> Result<PlannedState> {
    let mut current = rustix::io::dup(base).context("duplicate relocate target descriptor")?;
    let components = normal_components(relative);
    for (index, name) in components.iter().enumerate() {
        let current_path = path_for_component(path, components.len(), index);
        match open_existing_directory(&current, name, &current_path, "cache-root path")? {
            Some(next) => current = next,
            None => return Ok(PlannedState::Create),
        }
    }
    validate_existing_tag(&current, path)?;
    Ok(PlannedState::AlreadyInitialized)
}

fn execute_roots(
    base: &OwnedFd,
    roots: Vec<PlannedRoot>,
    transaction: &mut Transaction,
    after_root: &mut dyn FnMut(usize, &Path) -> Result<()>,
) -> Result<InitializationReport> {
    let mut report = InitializationReport {
        initialized: Vec::new(),
        already_initialized: Vec::new(),
    };
    for (index, root) in roots.into_iter().enumerate() {
        let state = initialize_root(base, &root, transaction)?;
        let path = root
            .path
            .to_str()
            .expect("relocation plan paths were validated as UTF-8")
            .to_owned();
        match state {
            PlannedState::Create => report.initialized.push(path),
            PlannedState::AlreadyInitialized => report.already_initialized.push(path),
        }
        after_root(index, &root.path)?;
    }
    Ok(report)
}

fn initialize_root(
    base: &OwnedFd,
    root: &PlannedRoot,
    transaction: &mut Transaction,
) -> Result<PlannedState> {
    let mut current = rustix::io::dup(base).context("duplicate relocate target descriptor")?;
    let components = normal_components(&root.relative);
    let mut exact_created = false;
    for (index, name) in components.iter().enumerate() {
        let current_path = path_for_component(&root.path, components.len(), index);
        match open_existing_directory(&current, name, &current_path, "cache-root path")? {
            Some(next) => current = next,
            None => {
                let (next, created) = create_directory(&current, name, &current_path, transaction)?;
                if index + 1 == components.len() {
                    exact_created = created;
                }
                current = next;
            }
        }
    }
    if exact_created {
        create_tag(&current, &root.path, transaction)?;
        Ok(PlannedState::Create)
    } else {
        validate_existing_tag(&current, &root.path)?;
        Ok(PlannedState::AlreadyInitialized)
    }
}

fn create_directory(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
    transaction: &mut Transaction,
) -> Result<(OwnedFd, bool)> {
    let rollback_parent =
        rustix::io::dup(parent).context("duplicate parent descriptor for rollback")?;
    match mkdir_private_at(parent, name) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::EXIST => {
            let fd = open_directory_at(parent, name, path)?;
            let stat = stat_fd(&fd, path)?;
            require_existing_directory(&stat, path, "existing cache-root path")?;
            return Ok((fd, false));
        }
        Err(error) => return Err(fs_error("create directory", path, error)),
    }

    let record = transaction.record_unknown(rollback_parent, name, path, CreatedKind::Directory);
    let stat = stat_at(parent, name)
        .map_err(|error| fs_error("inspect created directory", path, error))?;
    require_kind(&stat, CreatedKind::Directory, path, "created directory")?;
    transaction.set_identity(record, identity(&stat, CreatedKind::Directory));
    let fd = open_directory_at(parent, name, path)?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o700))
        .map_err(|error| fs_error("set created directory mode", path, error))?;
    let opened = stat_fd(&fd, path)?;
    require_same_identity(&stat, &opened, path)?;
    require_created(&opened, path, CreatedKind::Directory, 0o700)?;
    Ok((fd, true))
}

fn mkdir_private_at(parent: &OwnedFd, name: &OsStr) -> rustix::io::Result<()> {
    let _lock = match UMASK_LOCK.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    let previous = rustix::process::umask(PRIVATE_UMASK);
    let _restore = UmaskRestore(previous);
    rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700))
}

fn create_tag(root: &OwnedFd, root_path: &Path, transaction: &mut Transaction) -> Result<()> {
    let tag_path = root_path.join(CACHEDIR_TAG);
    let rollback_parent =
        rustix::io::dup(root).context("duplicate cache-root descriptor for rollback")?;
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(root, CACHEDIR_TAG, flags, Mode::from_raw_mode(0o600))
        .map_err(|error| fs_error("create CACHEDIR.TAG", &tag_path, error))?;
    let record = transaction.record_unknown(
        rollback_parent,
        OsStr::new(CACHEDIR_TAG),
        &tag_path,
        CreatedKind::File,
    );
    let stat = stat_fd(&fd, &tag_path)?;
    require_kind(&stat, CreatedKind::File, &tag_path, "created CACHEDIR.TAG")?;
    transaction.set_identity(record, identity(&stat, CreatedKind::File));
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600))
        .map_err(|error| fs_error("set CACHEDIR.TAG mode", &tag_path, error))?;
    write_all(&fd, TAG_CONTENT, &tag_path)?;
    let verified = stat_fd(&fd, &tag_path)?;
    require_same_identity(&stat, &verified, &tag_path)?;
    require_created(&verified, &tag_path, CreatedKind::File, 0o600)
}

fn validate_existing_tag(root: &OwnedFd, root_path: &Path) -> Result<()> {
    // A pyvenv.cfg marks a virtualenv, which the scanner vetoes as not a pure
    // cache (its metadata probe follows a symlink, so a symlinked pyvenv.cfg
    // counts). --init must not report such a root already initialized either, so
    // a regular file or a symlink named pyvenv.cfg is refused alike.
    match stat_at(root, "pyvenv.cfg") {
        Ok(stat)
            if matches!(
                FileType::from_raw_mode(stat.st_mode),
                FileType::RegularFile | FileType::Symlink
            ) =>
        {
            anyhow::bail!(
                "cache root {} is a virtualenv (pyvenv.cfg present), not a pure cache; refusing to initialize it",
                root_path.display()
            )
        }
        Ok(_) => {}
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => {
            return Err(fs_error(
                "inspect pyvenv.cfg",
                &root_path.join("pyvenv.cfg"),
                error,
            ));
        }
    }
    let tag_path = root_path.join(CACHEDIR_TAG);
    let inspected = match stat_at(root, CACHEDIR_TAG) {
        Ok(stat) => stat,
        Err(error) if error == rustix::io::Errno::NOENT => {
            anyhow::bail!(
                "cache root {} existed before this run without a valid CACHEDIR.TAG; refusing to initialize it",
                root_path.display()
            )
        }
        Err(error) => return Err(fs_error("inspect existing CACHEDIR.TAG", &tag_path, error)),
    };
    require_kind(
        &inspected,
        CreatedKind::File,
        &tag_path,
        "existing CACHEDIR.TAG",
    )?;
    require_owned_safe(&inspected, &tag_path, "existing CACHEDIR.TAG")?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = rustix::fs::openat(root, CACHEDIR_TAG, flags, Mode::empty())
        .map_err(|error| fs_error("open existing CACHEDIR.TAG", &tag_path, error))?;
    let opened = stat_fd(&fd, &tag_path)?;
    require_same_identity(&inspected, &opened, &tag_path)?;
    require_kind(&opened, CreatedKind::File, &tag_path, "opened CACHEDIR.TAG")?;
    require_owned_safe(&opened, &tag_path, "opened CACHEDIR.TAG")?;
    if !has_exact_signature(&fd, &tag_path)? {
        anyhow::bail!(
            "cache root {} has an invalid CACHEDIR.TAG; refusing to initialize it",
            root_path.display()
        );
    }
    Ok(())
}

fn has_exact_signature(fd: &OwnedFd, path: &Path) -> Result<bool> {
    let mut prefix = vec![0_u8; degu_adapters::SIGNATURE_PROBE_LEN];
    let mut read = 0;
    while read < prefix.len() {
        match rustix::io::read(fd, &mut prefix[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(fs_error("read existing CACHEDIR.TAG", path, error)),
        }
    }
    prefix.truncate(read);
    // Share the scanner's byte-level predicate so `--init` and scan never
    // disagree on a valid tag (a CRLF-terminated signature included).
    Ok(degu_adapters::prefix_has_signature(&prefix))
}

fn write_all(fd: &OwnedFd, mut bytes: &[u8], path: &Path) -> Result<()> {
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(0) => anyhow::bail!("write CACHEDIR.TAG {} returned zero bytes", path.display()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(fs_error("write CACHEDIR.TAG", path, error)),
        }
    }
    Ok(())
}

fn open_existing_directory(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
    label: &str,
) -> Result<Option<OwnedFd>> {
    let inspected = match stat_at(parent, name) {
        Ok(stat) => stat,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(fs_error("inspect directory", path, error)),
    };
    require_kind(&inspected, CreatedKind::Directory, path, label)?;
    let fd = open_directory_at(parent, name, path)?;
    let opened = stat_fd(&fd, path)?;
    require_same_identity(&inspected, &opened, path)?;
    require_existing_directory(&opened, path, label)?;
    Ok(Some(fd))
}

fn open_directory_at<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    path: &Path,
) -> Result<OwnedFd> {
    rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| fs_error("open directory without following symlinks", path, error))
}

fn stat_at<Fd: AsFd, P: rustix::path::Arg>(parent: Fd, name: P) -> rustix::io::Result<Stat> {
    rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
}

fn stat_fd(fd: &OwnedFd, path: &Path) -> Result<Stat> {
    rustix::fs::fstat(fd).map_err(|error| fs_error("inspect opened object", path, error))
}

fn require_existing_directory(stat: &Stat, path: &Path, label: &str) -> Result<()> {
    require_kind(stat, CreatedKind::Directory, path, label)?;
    require_owned_safe(stat, path, label)
}

fn require_owned_safe(stat: &Stat, path: &Path, label: &str) -> Result<()> {
    let euid = rustix::process::geteuid().as_raw();
    if stat.st_uid != euid {
        anyhow::bail!(
            "{label} {} is owned by UID {}, not effective UID {euid}",
            path.display(),
            stat.st_uid
        );
    }
    if stat.st_mode & SHARED_WRITE_MASK != 0 {
        anyhow::bail!("{label} {} is group- or world-writable", path.display());
    }
    Ok(())
}

fn require_created(
    stat: &Stat,
    path: &Path,
    kind: CreatedKind,
    mode: rustix::fs::RawMode,
) -> Result<()> {
    require_kind(stat, kind, path, "created object")?;
    let euid = rustix::process::geteuid().as_raw();
    if stat.st_uid != euid || stat.st_mode & PERMISSION_MASK != mode {
        anyhow::bail!(
            "created object {} failed owner/mode verification (uid {}, mode {:04o})",
            path.display(),
            stat.st_uid,
            stat.st_mode & PERMISSION_MASK
        );
    }
    Ok(())
}

fn require_kind(stat: &Stat, kind: CreatedKind, path: &Path, label: &str) -> Result<()> {
    let expected = match kind {
        CreatedKind::Directory => FileType::Directory,
        CreatedKind::File => FileType::RegularFile,
    };
    if FileType::from_raw_mode(stat.st_mode) != expected {
        anyhow::bail!("{label} {} is not a real {}", path.display(), kind.name());
    }
    Ok(())
}

fn require_same_identity(before: &Stat, after: &Stat, path: &Path) -> Result<()> {
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || FileType::from_raw_mode(before.st_mode) != FileType::from_raw_mode(after.st_mode)
    {
        anyhow::bail!(
            "{} changed identity while it was being verified",
            path.display()
        );
    }
    Ok(())
}

fn identity(stat: &Stat, kind: CreatedKind) -> Identity {
    Identity {
        device: stat.st_dev,
        inode: stat.st_ino,
        kind,
    }
}

fn normal_components(path: &Path) -> Vec<&OsStr> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => name,
            _ => unreachable!("subdirectories were validated before mutation"),
        })
        .collect()
}

fn path_for_component(path: &Path, component_count: usize, index: usize) -> PathBuf {
    let mut current = path.to_path_buf();
    for _ in index + 1..component_count {
        current.pop();
    }
    current
}

fn fs_error(action: &str, path: &Path, error: rustix::io::Errno) -> anyhow::Error {
    anyhow::anyhow!(
        "{action} {}: {}",
        path.display(),
        std::io::Error::from(error)
    )
}

impl CreatedKind {
    fn name(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "regular file",
        }
    }

    fn unlink_flags(self) -> AtFlags {
        match self {
            Self::Directory => AtFlags::REMOVEDIR,
            Self::File => AtFlags::empty(),
        }
    }
}

impl Drop for UmaskRestore {
    fn drop(&mut self) {
        rustix::process::umask(self.0);
    }
}

impl Transaction {
    fn record_unknown(
        &mut self,
        parent: OwnedFd,
        name: &OsStr,
        path: &Path,
        kind: CreatedKind,
    ) -> usize {
        self.created.push(CreatedEntry {
            parent,
            name: name.to_owned(),
            path: path.to_path_buf(),
            kind,
            identity: None,
        });
        self.created.len() - 1
    }

    fn set_identity(&mut self, index: usize, identity: Identity) {
        self.created[index].identity = Some(identity);
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "rollback is itself the identity-checked fd-relative deletion engine for relocate init"
    )]
    fn rollback(&mut self) -> std::result::Result<(), Vec<String>> {
        let mut residue = Vec::new();
        for entry in self.created.iter().rev() {
            let expected = match entry.identity {
                Some(identity) => identity,
                None => {
                    residue.push(format!("{} (identity unavailable)", entry.path.display()));
                    continue;
                }
            };
            let current = match stat_at(&entry.parent, &entry.name) {
                Ok(stat) => stat,
                Err(error) if error == rustix::io::Errno::NOENT => continue,
                Err(error) => {
                    residue.push(format!(
                        "{} ({})",
                        entry.path.display(),
                        std::io::Error::from(error)
                    ));
                    continue;
                }
            };
            let current_identity = identity(&current, entry.kind);
            if current_identity.device != expected.device
                || current_identity.inode != expected.inode
                || current_identity.kind != expected.kind
                || require_kind(&current, entry.kind, &entry.path, "rollback object").is_err()
            {
                residue.push(format!("{} (identity changed)", entry.path.display()));
                continue;
            }
            if let Err(error) =
                rustix::fs::unlinkat(&entry.parent, &entry.name, entry.kind.unlink_flags())
            {
                residue.push(format!(
                    "{} ({})",
                    entry.path.display(),
                    std::io::Error::from(error)
                ));
            }
        }
        if residue.is_empty() {
            Ok(())
        } else {
            Err(residue)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    /// A tempdir whose own mode is owner-only, so `require_creation_parent`
    /// trusts it as a relocate-target parent regardless of the ambient umask.
    fn private_scratch() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// Strips group/other write from a fixture tree so an ambient umask of 002
    /// cannot leave a directory the safety checks refuse before the case under
    /// test; symlinks and non-regular files (a FIFO tag) are left untouched.
    fn strip_shared_write(root: &Path) {
        let Ok(metadata) = std::fs::symlink_metadata(root) else {
            return;
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return;
        }
        if file_type.is_dir() || file_type.is_file() {
            let mode = metadata.permissions().mode() & !0o022;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        if file_type.is_dir() {
            for entry in std::fs::read_dir(root).unwrap().flatten() {
                strip_shared_write(&entry.path());
            }
        }
    }

    fn valid_tag(root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join(CACHEDIR_TAG), TAG_CONTENT).unwrap();
    }

    #[test]
    fn invalid_subdirectories_are_rejected_before_target_creation() {
        let scratch = private_scratch();
        for (index, subdir) in ["", ".", "..", "../pip", "/absolute", "one/../two"]
            .into_iter()
            .enumerate()
        {
            let target = scratch.path().join(format!("target-{index}"));
            let result = initialize(&target, &[PathBuf::from(subdir)]);
            assert!(result.is_err(), "{subdir:?} must be rejected");
            assert!(!target.exists(), "{subdir:?} mutated the target");
        }
    }

    #[test]
    fn duplicate_roots_are_initialized_once() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");

        let report = initialize(&target, &[PathBuf::from("pip"), PathBuf::from("pip")]).unwrap();

        assert_eq!(report.initialized.len(), 1);
        assert_eq!(
            report.initialized[0],
            target.join("pip").display().to_string()
        );
    }

    #[test]
    fn unsafe_existing_target_is_rejected_without_creating_roots() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o770)).unwrap();

        let result = initialize(&target, &[PathBuf::from("pip")]);

        assert!(result.is_err());
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    }

    #[test]
    fn symlink_root_is_rejected_without_following_it() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        let outside = scratch.path().join("outside");
        std::fs::create_dir(&target).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, target.join("pip")).unwrap();
        strip_shared_write(&target);

        let result = initialize(&target, &[PathBuf::from("pip")]);

        assert!(result.is_err());
        assert!(!outside.join(CACHEDIR_TAG).exists());
        assert!(
            std::fs::symlink_metadata(target.join("pip"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn symlink_tag_is_rejected_without_following_it() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        let root = target.join("pip");
        let outside = scratch.path().join("outside-tag");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&outside, b"outside bytes").unwrap();
        std::os::unix::fs::symlink(&outside, root.join(CACHEDIR_TAG)).unwrap();
        strip_shared_write(&target);

        let result = initialize(&target, &[PathBuf::from("pip")]);

        assert!(result.is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"outside bytes");
        assert!(
            std::fs::symlink_metadata(root.join(CACHEDIR_TAG))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn fifo_tag_is_rejected_without_opening_it() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        let root = target.join("pip");
        let tag = root.join(CACHEDIR_TAG);
        std::fs::create_dir_all(&root).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&tag)
            .status()
            .unwrap();
        assert!(status.success());
        strip_shared_write(&target);

        let result = initialize(&target, &[PathBuf::from("pip")]);

        assert!(result.is_err());
        assert!(
            std::fs::symlink_metadata(tag)
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }

    #[test]
    fn mid_run_failure_rolls_back_only_initializer_creations() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let existing = target.join("existing");
        valid_tag(&existing);
        let payload = existing.join("payload.bin");
        std::fs::write(&payload, b"pre-existing bytes").unwrap();
        strip_shared_write(&target);
        let blocked = target.join("blocked");
        let blocked_for_hook = blocked.clone();
        let mut hook = move |index: usize, _path: &Path| {
            if index == 1 {
                std::fs::create_dir(&blocked_for_hook)?;
                std::fs::write(blocked_for_hook.join("payload.bin"), b"concurrent bytes")?;
            }
            Ok(())
        };

        let result = initialize_with_hook(
            &target,
            &[
                PathBuf::from("existing"),
                PathBuf::from("created"),
                PathBuf::from("blocked"),
            ],
            &mut hook,
        );

        let error = result.err().expect("initialization must fail").to_string();
        assert!(error.contains("were rolled back"), "{error}");
        assert!(!target.join("created").exists());
        assert_eq!(std::fs::read(payload).unwrap(), b"pre-existing bytes");
        assert_eq!(
            std::fs::read(blocked.join("payload.bin")).unwrap(),
            b"concurrent bytes"
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the test replaces an initialized path to exercise rollback's identity mismatch guard"
    )]
    fn rollback_identity_mismatch_is_reported_and_not_deleted() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        std::fs::create_dir(&target).unwrap();
        strip_shared_write(&target);
        let created = target.join("created");
        let blocked = target.join("blocked");
        let created_for_hook = created.clone();
        let blocked_for_hook = blocked.clone();
        let mut hook = move |index: usize, _path: &Path| {
            if index == 0 {
                std::fs::remove_file(created_for_hook.join(CACHEDIR_TAG))?;
                std::fs::remove_dir(&created_for_hook)?;
                std::fs::create_dir(&created_for_hook)?;
                std::fs::write(created_for_hook.join("replacement.bin"), b"replacement")?;
                std::fs::create_dir(&blocked_for_hook)?;
            }
            Ok(())
        };

        let result = initialize_with_hook(
            &target,
            &[PathBuf::from("created"), PathBuf::from("blocked")],
            &mut hook,
        );

        let error = result.err().expect("initialization must fail").to_string();
        assert!(error.contains("rollback left residue"), "{error}");
        assert!(error.contains(created.to_str().unwrap()), "{error}");
        assert_eq!(
            std::fs::read(created.join("replacement.bin")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn existing_target_under_a_group_writable_parent_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        let target = scratch.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();

        let result = initialize(&target, &[PathBuf::from("pip")]);

        let error = format!(
            "{:#}",
            result.err().expect("an untrusted parent must be refused")
        );
        assert!(error.contains("not a trusted namespace"), "{error}");
        assert!(!target.join("pip").exists());
    }

    #[test]
    fn a_group_writable_grandparent_is_refused() {
        for create_target in [false, true] {
            let grandparent = tempfile::tempdir().unwrap();
            std::fs::set_permissions(grandparent.path(), std::fs::Permissions::from_mode(0o775))
                .unwrap();
            let private_parent = grandparent.path().join("private-parent");
            std::fs::create_dir(&private_parent).unwrap();
            std::fs::set_permissions(&private_parent, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let target = private_parent.join("cache");
            if create_target {
                std::fs::create_dir(&target).unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
            }

            let error = format!(
                "{:#}",
                initialize(&target, &[PathBuf::from("pip")])
                    .err()
                    .expect("a group-writable grandparent must be refused")
            );
            assert!(error.contains("not a trusted namespace"), "{error}");
            assert!(!target.join("pip").exists());
        }
    }

    #[test]
    fn a_symlink_in_a_trusted_namespace_is_followed() {
        let scratch = private_scratch();
        let real = scratch.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let target = link.join("cache");

        let report = initialize(&target, &[PathBuf::from("pip")]).unwrap();

        assert_eq!(report.initialized.len(), 1);
        assert!(real.join("cache/pip/CACHEDIR.TAG").exists());
    }

    #[test]
    fn a_symlink_in_a_group_writable_namespace_is_refused() {
        let scratch = private_scratch();
        let shared = scratch.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let real = scratch.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, shared.join("link")).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
        let target = shared.join("link").join("cache");

        let error = format!(
            "{:#}",
            initialize(&target, &[PathBuf::from("pip")])
                .err()
                .expect("a symlink in a group-writable namespace must be refused")
        );
        assert!(error.contains("not a trusted namespace"), "{error}");
        assert!(!real.join("cache").exists());
    }

    #[test]
    fn a_symlink_target_through_a_group_writable_dir_is_refused() {
        let scratch = private_scratch();
        let shared = scratch.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let inner = shared.join("inner");
        std::fs::create_dir(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&inner, &link).unwrap();
        let target = link.join("cache");

        let error = format!(
            "{:#}",
            initialize(&target, &[PathBuf::from("pip")])
                .err()
                .expect("a symlink target chain through a group-writable dir must be refused")
        );
        assert!(error.contains("not a trusted namespace"), "{error}");
        assert!(!inner.join("cache").exists());
    }

    #[test]
    fn a_target_swapped_after_initialization_is_refused_before_output() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        std::fs::create_dir(&target).unwrap();
        strip_shared_write(&target);
        let moved = scratch.path().join("moved");
        let target_for_hook = target.clone();
        let moved_for_hook = moved.clone();
        let mut hook = move |_index: usize, _path: &Path| {
            std::fs::rename(&target_for_hook, &moved_for_hook)?;
            std::fs::create_dir(&target_for_hook)?;
            Ok(())
        };

        let result = initialize_with_hook(&target, &[PathBuf::from("pip")], &mut hook);

        let error = format!(
            "{:#}",
            result.err().expect("a swapped target must be refused")
        );
        assert!(error.contains("no longer names"), "{error}");
        assert!(!target.join("pip").exists());
    }

    #[test]
    fn a_crlf_terminated_signature_tag_is_accepted() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        let root = target.join("pip");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(CACHEDIR_TAG),
            b"Signature: 8a477f597d28d172789f06886806bc55\r\n",
        )
        .unwrap();
        strip_shared_write(&target);

        let report = initialize(&target, &[PathBuf::from("pip")]).unwrap();

        assert_eq!(report.already_initialized.len(), 1);
        assert!(report.initialized.is_empty());
    }

    #[test]
    fn a_root_with_a_pyvenv_cfg_is_refused_even_with_a_valid_tag() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        let root = target.join("pip");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(CACHEDIR_TAG), TAG_CONTENT).unwrap();
        std::fs::write(root.join("pyvenv.cfg"), b"home = /usr\n").unwrap();
        strip_shared_write(&target);

        let error = format!(
            "{:#}",
            initialize(&target, &[PathBuf::from("pip")])
                .err()
                .expect("a virtualenv root must be refused")
        );
        assert!(error.contains("virtualenv"), "{error}");
    }

    #[test]
    fn a_symlinked_pyvenv_cfg_is_refused() {
        let scratch = private_scratch();
        let target = scratch.path().join("target");
        let root = target.join("pip");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(CACHEDIR_TAG), TAG_CONTENT).unwrap();
        let outside = scratch.path().join("real-pyvenv");
        std::fs::write(&outside, b"home = /usr\n").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("pyvenv.cfg")).unwrap();
        strip_shared_write(&target);

        let error = format!(
            "{:#}",
            initialize(&target, &[PathBuf::from("pip")])
                .err()
                .expect("a symlinked pyvenv.cfg must be refused")
        );
        assert!(error.contains("virtualenv"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_procfs_magic_link_target_is_refused() {
        // /proc/self/cwd is a process-dependent magic link: degu would resolve it
        // to its own cwd, but the exported lexical path resolves elsewhere in the
        // sourcing shell. It must be refused rather than followed.
        let error = format!(
            "{:#}",
            initialize(Path::new("/proc/self/cwd/cache"), &[PathBuf::from("pip")])
                .err()
                .expect("a procfs magic-link target must be refused")
        );
        assert!(
            error.contains("procfs") || error.contains("process"),
            "{error}"
        );
    }
}
