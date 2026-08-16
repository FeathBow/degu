use super::*;

pub(super) fn open_or_publish_directory(
    parent: &OwnedFd,
    final_name: &OsStr,
    final_path: &Path,
    owner: u32,
    kind: DirectoryKind,
    backend_probe: BackendProbe,
) -> Result<(ValidatedDirectory, Option<CreatedEntry>), ActivationAnchorProvisioningError> {
    match open_directory(parent, final_name, final_path) {
        Ok(fd) => {
            let validated = validate_directory(&fd, final_path, owner, kind, backend_probe)?;
            validate_binding(parent, final_name, &fd, final_path, validated.identity)?;
            return Ok((validated, None));
        }
        Err(ActivationAnchorProvisioningError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let temp_name = private_temp_name()?;
    let temp_path = final_path.with_file_name(&temp_name);
    rustix::fs::mkdirat(parent, &temp_name, PRIVATE_CREATE_MODE)
        .map_err(|error| io_error(&temp_path, error.into()))?;
    let temp_fd = match open_directory(parent, &temp_name, &temp_path) {
        Ok(fd) => fd,
        Err(error) => {
            return Err(ActivationAnchorProvisioningError::RollbackResidue {
                failure: error.to_string(),
                residue: vec![temp_path],
            });
        }
    };
    let birth_identity = strong_identity_fd(&temp_fd).map_err(|_| {
        ActivationAnchorProvisioningError::RollbackResidue {
            failure: "strong birth identity is unavailable for the private initializer".into(),
            residue: vec![temp_path.clone()],
        }
    })?;
    if let Err(error) = validate_binding(parent, &temp_name, &temp_fd, &temp_path, birth_identity) {
        return cleanup_temp_after_failure(parent, &temp_name, &temp_path, birth_identity, error);
    }

    let initialize = (|| {
        let mode = match kind {
            DirectoryKind::Public => PUBLIC_MODE,
            DirectoryKind::System | DirectoryKind::Leaf(_) | DirectoryKind::PrivateLock => {
                PRIVATE_LOCK_MODE
            }
        };
        rustix::fs::fchmod(&temp_fd, Mode::from_raw_mode(mode as _))
            .map_err(|error| io_error(&temp_path, error.into()))?;
        if matches!(kind, DirectoryKind::Leaf(_)) {
            fchown_uid(&temp_fd, owner).map_err(|error| io_error(&temp_path, error))?;
        }
        let validated = validate_directory(&temp_fd, &temp_path, owner, kind, backend_probe)?;
        validate_binding(parent, &temp_name, &temp_fd, &temp_path, birth_identity)?;
        sync_directory(&temp_fd, &temp_path)?;
        sync_directory(parent, final_path.parent().unwrap_or(Path::new("/")))?;
        Ok(validated)
    })();
    if let Err(error) = initialize {
        return cleanup_temp_after_failure(parent, &temp_name, &temp_path, birth_identity, error);
    }

    let published_rollback =
        match prepared_created_entry(parent, final_name, final_path, birth_identity) {
            Ok(entry) => entry,
            Err(error) => {
                return cleanup_temp_after_failure(
                    parent,
                    &temp_name,
                    &temp_path,
                    birth_identity,
                    error,
                );
            }
        };

    #[cfg(test)]
    if let BackendProbe::LoseNoreplaceRaceAndBlockCleanupAt(target) = backend_probe
        && final_name == OsStr::new(target)
    {
        // Deterministically model a concurrent winner, then make this
        // invocation's initializer non-empty so collision cleanup fails.
        rustix::fs::mkdirat(parent, final_name, PRIVATE_CREATE_MODE)
            .map_err(|error| io_error(final_path, error.into()))?;
        rustix::fs::mkdirat(
            &temp_fd,
            OsStr::new(TEST_CLEANUP_BLOCKER_NAME),
            PRIVATE_CREATE_MODE,
        )
        .map_err(|error| io_error(&temp_path, error.into()))?;
    }

    match rustix::fs::renameat_with(
        parent,
        &temp_name,
        parent,
        final_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            let published = (|| {
                sync_directory(parent, final_path.parent().unwrap_or(Path::new("/")))?;
                validate_binding(parent, final_name, &temp_fd, final_path, birth_identity)?;
                validate_directory(&temp_fd, final_path, owner, kind, backend_probe)
            })();
            match published {
                Ok(validated) => Ok((validated, Some(published_rollback))),
                Err(error) => cleanup_temp_after_failure(
                    parent,
                    final_name,
                    final_path,
                    birth_identity,
                    error,
                ),
            }
        }
        Err(rustix::io::Errno::EXIST) => {
            if let Err(failure) =
                remove_identity_matched_empty(parent, &temp_name, &temp_path, birth_identity)
            {
                return Err(ActivationAnchorProvisioningError::RollbackResidue {
                    failure: failure.to_string(),
                    residue: vec![temp_path],
                });
            }
            let fd = open_directory(parent, final_name, final_path)?;
            let validated = validate_directory(&fd, final_path, owner, kind, backend_probe)?;
            validate_binding(parent, final_name, &fd, final_path, validated.identity)?;
            Ok((validated, None))
        }
        Err(error) => cleanup_temp_after_failure(
            parent,
            &temp_name,
            &temp_path,
            birth_identity,
            io_error(final_path, error.into()),
        ),
    }
}

fn cleanup_temp_after_failure<T>(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
    identity: StrongObjectIdentity,
    failure: ActivationAnchorProvisioningError,
) -> Result<T, ActivationAnchorProvisioningError> {
    match remove_identity_matched_empty(parent, name, path, identity) {
        Ok(()) => Err(failure),
        Err(_) => Err(ActivationAnchorProvisioningError::RollbackResidue {
            failure: failure.to_string(),
            residue: vec![path.to_path_buf()],
        }),
    }
}

#[allow(clippy::disallowed_methods)] // rollback: held parent, no-follow, strong identity, empty dir only
fn remove_identity_matched_empty(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
    identity: StrongObjectIdentity,
) -> Result<(), ActivationAnchorProvisioningError> {
    let fd = open_directory(parent, name, path)?;
    if strong_identity_fd(&fd).ok() != Some(identity)
        || !binding_matches(parent, name, &fd).map_err(|error| io_error(path, error))?
    {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "refusing to remove an initializer whose identity or binding changed",
        });
    }
    rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR)
        .map_err(|error| io_error(path, error.into()))?;
    sync_directory(parent, path.parent().unwrap_or(Path::new("/")))
}

fn private_temp_name() -> Result<OsString, ActivationAnchorProvisioningError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|source| ActivationAnchorProvisioningError::Io {
        path: PathBuf::from("platform random source"),
        source: io::Error::other(source),
    })?;
    let mut name = String::from(PRIVATE_TEMP_PREFIX);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(name.into())
}

pub(super) fn open_directory(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
) -> Result<OwnedFd, ActivationAnchorProvisioningError> {
    rustix::fs::openat(parent, name, OPEN_DIRECTORY, Mode::empty()).map_err(|error| match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
            ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "entry is not a no-follow directory",
            }
        }
        error => io_error(path, error.into()),
    })
}

pub(super) fn validate_directory(
    fd: &OwnedFd,
    path: &Path,
    owner: u32,
    kind: DirectoryKind,
    backend_probe: BackendProbe,
) -> Result<ValidatedDirectory, ActivationAnchorProvisioningError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "entry is not a directory",
        });
    }
    if stat.st_uid != owner {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: match kind {
                DirectoryKind::Leaf(_) => "activation-anchor leaf has the wrong owner",
                DirectoryKind::System | DirectoryKind::Public | DirectoryKind::PrivateLock
                    if owner != 0 =>
                {
                    "self-managed activation-anchor namespace component has the wrong owner"
                }
                DirectoryKind::System | DirectoryKind::Public | DirectoryKind::PrivateLock => {
                    "activation-anchor namespace component is not root-owned"
                }
            },
        });
    }
    let mode = stat.st_mode as u32 & 0o7777;
    match kind {
        DirectoryKind::System if mode & 0o022 != 0 => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "system activation-anchor component grants group or other write",
            });
        }
        DirectoryKind::Public if mode != PUBLIC_MODE => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "public activation-anchor component mode is not exactly 0755",
            });
        }
        DirectoryKind::PrivateLock if mode != PRIVATE_LOCK_MODE => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "private provisioning lock mode is not exactly 0700",
            });
        }
        DirectoryKind::Leaf(_) if mode != LEAF_MODE => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "activation-anchor leaf mode is not exactly 0700",
            });
        }
        DirectoryKind::System
        | DirectoryKind::Public
        | DirectoryKind::PrivateLock
        | DirectoryKind::Leaf(_) => {}
    }
    require_held_fd_acl_absent(fd).map_err(|reason| certification_error(path, reason))?;
    let backend = match backend_probe {
        BackendProbe::Real => certify_held_fd_backend(fd),
        #[cfg(test)]
        BackendProbe::Fixed(backend) => Ok(backend),
        #[cfg(test)]
        BackendProbe::FailAt(name) if path.file_name() == Some(OsStr::new(name)) => {
            Err(CertificationError::InspectionFailed)
        }
        #[cfg(test)]
        BackendProbe::FailAt(_) => Ok(CertifiedLocalBackend::Ext4),
        #[cfg(test)]
        BackendProbe::LoseNoreplaceRaceAndBlockCleanupAt(_) => certify_held_fd_backend(fd),
    }
    .map_err(|reason| certification_error(path, reason))?;
    let identity =
        strong_identity_fd(fd).map_err(|_| ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "strong birth identity is unavailable",
        })?;
    Ok(ValidatedDirectory {
        fd: rustix::io::fcntl_dupfd_cloexec(fd, 0).map_err(|error| io_error(path, error.into()))?,
        identity,
        backend,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn revalidate_account_base(
    initial_home: &Path,
    expected_identity: (u64, u64),
    account_home_lookup: &mut dyn FnMut() -> Result<PathBuf, AccountBaseError>,
) -> Result<(), ActivationAnchorProvisioningError> {
    let current_home = account_home_lookup()?;
    if current_home != initial_home {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: initial_home.to_path_buf(),
            reason: "account database home changed during self-managed provisioning",
        });
    }
    let rebound = degu_walk::resolve_trusted_directory(&current_home, "self-managed account base")
        .map_err(|source| io_error(&current_home, source))?;
    if directory_identity(&rebound, &current_home)? != expected_identity {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: current_home,
            reason: "self-managed account base binding changed during provisioning",
        });
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn preflight_runtime_parent(
    leaf_path: &Path,
    held_parent: &OwnedFd,
) -> Result<(), ActivationAnchorProvisioningError> {
    let (runtime_parent, runtime_name, runtime_parent_path) = open_authenticated_parent(leaf_path)
        .map_err(
            |source| ActivationAnchorProvisioningError::RuntimeIncompatible {
                path: leaf_path.to_path_buf(),
                source,
            },
        )?;
    if runtime_name != leaf_path.file_name().unwrap_or_default()
        || runtime_parent_path != leaf_path.parent().unwrap_or(Path::new("/"))
        || directory_identity(&runtime_parent, &runtime_parent_path)?
            != directory_identity(held_parent, &runtime_parent_path)?
    {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: leaf_path.to_path_buf(),
            reason: "runtime ancestry does not bind the provisioning parent",
        });
    }
    Ok(())
}

pub(super) fn directory_identity(
    fd: &OwnedFd,
    path: &Path,
) -> Result<(u64, u64), ActivationAnchorProvisioningError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

pub(super) fn validate_binding(
    parent: &OwnedFd,
    name: &OsStr,
    fd: &OwnedFd,
    path: &Path,
    identity: StrongObjectIdentity,
) -> Result<(), ActivationAnchorProvisioningError> {
    if !binding_matches(parent, name, fd).map_err(|error| io_error(path, error))?
        || strong_identity_fd(fd).ok() != Some(identity)
    {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "held directory is no longer the exact parent entry",
        });
    }
    Ok(())
}

fn binding_matches(parent: &OwnedFd, name: &OsStr, fd: &OwnedFd) -> io::Result<bool> {
    let entry =
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    let held = rustix::fs::fstat(fd).map_err(io::Error::from)?;
    Ok(entry.st_dev == held.st_dev
        && entry.st_ino == held.st_ino
        && FileType::from_raw_mode(entry.st_mode) == FileType::Directory)
}

pub(super) fn chain_entry(
    parent: &OwnedFd,
    name: &OsStr,
    child: &OwnedFd,
    path: &Path,
    identity: StrongObjectIdentity,
    kind: DirectoryKind,
) -> Result<ChainEntry, ActivationAnchorProvisioningError> {
    Ok(ChainEntry {
        parent: rustix::io::fcntl_dupfd_cloexec(parent, 0)
            .map_err(|error| io_error(path, error.into()))?,
        name: name.to_os_string(),
        child: rustix::io::fcntl_dupfd_cloexec(child, 0)
            .map_err(|error| io_error(path, error.into()))?,
        path: path.to_path_buf(),
        identity,
        kind,
    })
}

fn prepared_created_entry(
    parent: &OwnedFd,
    final_name: &OsStr,
    final_path: &Path,
    identity: StrongObjectIdentity,
) -> Result<CreatedEntry, ActivationAnchorProvisioningError> {
    Ok(CreatedEntry {
        parent: rustix::io::fcntl_dupfd_cloexec(parent, 0)
            .map_err(|error| io_error(final_path, error.into()))?,
        name: final_name.to_os_string(),
        path: final_path.to_path_buf(),
        identity,
    })
}

pub(super) fn rollback_created(created: &mut Vec<CreatedEntry>) -> Vec<PathBuf> {
    let mut residue = Vec::new();
    while let Some(entry) = created.pop() {
        if remove_identity_matched_empty(&entry.parent, &entry.name, &entry.path, entry.identity)
            .is_err()
        {
            residue.push(entry.path);
        }
    }
    residue
}

fn fchown_uid(fd: &OwnedFd, uid: u32) -> io::Result<()> {
    debug_assert_ne!(uid, u32::MAX);
    // SAFETY: `fd` is held open and the public/core validators reject the
    // `(uid_t)-1` sentinel before this function is reachable.
    let result = unsafe { libc::fchown(fd.as_raw_fd(), uid, !0 as libc::gid_t) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn sync_directory(
    fd: &OwnedFd,
    path: &Path,
) -> Result<(), ActivationAnchorProvisioningError> {
    rustix::fs::fsync(fd).map_err(|error| io_error(path, error.into()))
}

fn certification_error(
    path: &Path,
    reason: CertificationError,
) -> ActivationAnchorProvisioningError {
    match reason {
        CertificationError::UnsupportedPlatform | CertificationError::UnsupportedFilesystem => {
            ActivationAnchorProvisioningError::UnsupportedBackend {
                path: path.to_path_buf(),
                reason,
            }
        }
        CertificationError::FilesystemMagicMismatch
        | CertificationError::NotDirectory
        | CertificationError::AclPresent => ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "entry type, ACL, or filesystem identity is unsafe",
        },
        reason => ActivationAnchorProvisioningError::Uncertain {
            path: path.to_path_buf(),
            reason,
        },
    }
}

pub(super) fn io_error(path: &Path, source: io::Error) -> ActivationAnchorProvisioningError {
    ActivationAnchorProvisioningError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn report_created_scaffold_failure(
    error: ActivationAnchorProvisioningError,
    created: &[PathBuf],
) -> ActivationAnchorProvisioningError {
    merge_rollback_residue(error, created)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn merge_rollback_residue(
    error: ActivationAnchorProvisioningError,
    additional: &[PathBuf],
) -> ActivationAnchorProvisioningError {
    if additional.is_empty() {
        return error;
    }
    match error {
        ActivationAnchorProvisioningError::RollbackResidue {
            failure,
            mut residue,
        } => {
            residue.extend_from_slice(additional);
            residue.sort();
            residue.dedup();
            ActivationAnchorProvisioningError::RollbackResidue { failure, residue }
        }
        error => {
            let mut residue = additional.to_vec();
            residue.sort();
            residue.dedup();
            ActivationAnchorProvisioningError::RollbackResidue {
                failure: error.to_string(),
                residue,
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn report_all_scaffold_failure(
    error: ActivationAnchorProvisioningError,
    flavor: ProvisioningFlavor<'_>,
    flavor_created: &[PathBuf],
    degu_created: bool,
    lock_created: bool,
) -> ActivationAnchorProvisioningError {
    let error = report_scaffold_failure(error, flavor, degu_created, lock_created);
    report_created_scaffold_failure(error, flavor_created)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn report_scaffold_failure(
    error: ActivationAnchorProvisioningError,
    flavor: ProvisioningFlavor<'_>,
    degu_created: bool,
    lock_created: bool,
) -> ActivationAnchorProvisioningError {
    let mut residue = Vec::new();
    let scaffold_path = |include_lock: bool| {
        let mut path = flavor.base().to_path_buf();
        for component in flavor
            .existing_prefix()
            .iter()
            .chain(flavor.scaffold_prefix())
            .chain(std::iter::once(&PRODUCT_COMPONENTS[0]))
        {
            path.push(component);
        }
        if include_lock {
            path.push(PROVISIONING_LOCK_NAME);
        }
        path
    };
    if degu_created {
        residue.push(scaffold_path(false));
    }
    if lock_created {
        residue.push(scaffold_path(true));
    }
    merge_rollback_residue(error, &residue)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn fixed_path(flavor: ProvisioningFlavor<'_>, uid: u32) -> PathBuf {
    let mut path = flavor.base().to_path_buf();
    for component in flavor
        .existing_prefix()
        .iter()
        .chain(flavor.scaffold_prefix())
        .chain(PRODUCT_COMPONENTS)
    {
        path.push(component);
    }
    path.push(uid.to_string());
    path
}
