use std::path::{Component, Path, PathBuf};

use degu_core::finding::{DispositionMode, Finding};

use super::super::{EntryIdentity, storage};

#[derive(Debug)]
pub(super) struct PreparedPolicy {
    pub(super) recovery_anchor: PathBuf,
    pub(super) canonical_source: PathBuf,
    pub(super) trash_root: PathBuf,
}

#[derive(Debug)]
pub(super) struct PreparedSource {
    canonical_source: PathBuf,
    canonical_source_parent: PathBuf,
}

impl PreparedSource {
    pub(super) fn canonical_source(&self) -> &Path {
        &self.canonical_source
    }
}

pub(super) fn assess_source(
    finding: &Finding,
    identity: &EntryIdentity,
) -> Result<PreparedSource, String> {
    require_disposition(finding.disposition().mode)?;
    let metadata = std::fs::symlink_metadata(finding.path())
        .map_err(|error| format!("failed to inspect sealed staging source: {error}"))?;
    if !metadata.is_dir() {
        return Err("sealed staging currently supports directories only".into());
    }
    if !identity
        .matches(finding.path())
        .map_err(|error| error.to_string())?
    {
        return Err("clean item identity changed before sealed staging policy checks".into());
    }
    let canonical_source = std::fs::canonicalize(finding.path())
        .map_err(|error| format!("failed to canonicalize sealed staging source: {error}"))?;
    let canonical_source_parent = canonical_source
        .parent()
        .ok_or_else(|| "sealed staging source has no canonical parent".to_string())?
        .to_path_buf();
    Ok(PreparedSource {
        canonical_source,
        canonical_source_parent,
    })
}

pub(super) fn complete(
    source: PreparedSource,
    lexical_trash: PathBuf,
) -> Result<PreparedPolicy, String> {
    let lexical_parent = lexical_trash
        .parent()
        .ok_or_else(|| "trash root has no parent".to_string())?;
    let canonical_parent = std::fs::canonicalize(lexical_parent)
        .map_err(|error| format!("failed to canonicalize prospective trash parent: {error}"))?;
    let trash_name = lexical_trash
        .file_name()
        .ok_or_else(|| "trash root has no name".to_string())?;
    let trash_root = canonical_parent.join(trash_name);

    let source_mount = storage::path_mount_id(&source.canonical_source)?;
    let destination_mount = storage::path_mount_id(&canonical_parent)?;
    require_same_mount(source_mount, destination_mount)?;
    let mount_owner_anchor =
        storage::resolve_mount_owner_anchor(&source.canonical_source, source_mount)?;
    let mount_owner_anchor = std::fs::canonicalize(&mount_owner_anchor)
        .map_err(|error| format!("failed to canonicalize mount owner anchor: {error}"))?;
    let recovery_anchor = select_recovery_anchor(
        source_mount,
        destination_mount,
        mount_owner_anchor,
        &source.canonical_source_parent,
        &trash_root,
        storage::path_mount_id,
        |path| std::fs::canonicalize(path),
    )?;
    confined_relative(&recovery_anchor, &source.canonical_source_parent)?;
    confined_relative(&recovery_anchor, &trash_root)?;
    degu_walk::resolve_trusted_directory(&recovery_anchor, "sealed-staging mount-domain anchor")
        .map_err(|error| format!("mount-domain anchor cannot be reopened safely: {error}"))?;
    Ok(PreparedPolicy {
        recovery_anchor,
        canonical_source: source.canonical_source,
        trash_root,
    })
}

fn require_disposition(mode: DispositionMode) -> Result<(), String> {
    if matches!(mode, DispositionMode::Eligible | DispositionMode::OptIn) {
        Ok(())
    } else {
        Err("sealed staging accepts only explicitly Eligible or opted-in findings".into())
    }
}

fn require_same_mount(source_mount: u64, destination_mount: u64) -> Result<(), String> {
    if source_mount == destination_mount {
        Ok(())
    } else {
        Err("sealed staging requires the source and trash destination on one mount".into())
    }
}

fn select_recovery_anchor<M, C>(
    source_mount: u64,
    destination_mount: u64,
    mount_owner_anchor: PathBuf,
    canonical_source_parent: &Path,
    trash_root: &Path,
    mut inspect_mount: M,
    mut canonicalize: C,
) -> Result<PathBuf, String>
where
    M: FnMut(&Path) -> Result<u64, String>,
    C: FnMut(&Path) -> std::io::Result<PathBuf>,
{
    require_same_mount(source_mount, destination_mount)?;
    let owner_confines_both = confined_relative(&mount_owner_anchor, canonical_source_parent)
        .and_then(|_| confined_relative(&mount_owner_anchor, trash_root))
        .is_ok();
    if owner_confines_both {
        return Ok(mount_owner_anchor);
    }

    let parent = mount_owner_anchor.parent().ok_or_else(|| {
        "mount-domain anchor has no parent for non-empty recovery locators".to_string()
    })?;
    if inspect_mount(parent)
        .map(|mount| mount != source_mount)
        .unwrap_or(true)
    {
        return Err(
            "source parent equals the writable mount root and no same-mount recovery ancestor exists"
                .into(),
        );
    }
    canonicalize(parent)
        .map_err(|error| format!("failed to canonicalize mount-domain anchor: {error}"))
}

pub(super) fn confined_relative(anchor: &Path, path: &Path) -> Result<PathBuf, String> {
    let relative = path.strip_prefix(anchor).map_err(|_| {
        format!(
            "sealed staging path is outside its mount-domain anchor: {}",
            path.display()
        )
    })?;
    if relative.as_os_str().is_empty() {
        return Ok(PathBuf::new());
    }
    let mut components = relative.components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || !components.all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "sealed staging path is not a confined mount-domain descendant: {}",
            path.display()
        ));
    }
    Ok(relative.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn directory_fixture() -> (tempfile::TempDir, PathBuf, Finding, EntryIdentity) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = temp.path().join("cache");
        std::fs::create_dir(&source).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        let finding = super::super::tests::finding_for_test(source.clone(), 1, 1);
        let identity = EntryIdentity::capture(&source).unwrap();
        (temp, source, finding, identity)
    }

    #[test]
    fn disposition_gate_accepts_only_production_modes() {
        assert!(require_disposition(DispositionMode::Eligible).is_ok());
        assert!(require_disposition(DispositionMode::OptIn).is_ok());
        assert_eq!(
            require_disposition(DispositionMode::ReportOnly).unwrap_err(),
            "sealed staging accepts only explicitly Eligible or opted-in findings"
        );
    }

    #[test]
    fn source_policy_rejects_non_directories_and_identity_changes() {
        let (temp, source, _, _) = directory_fixture();
        let file = temp.path().join("file");
        std::fs::write(&file, b"data").unwrap();
        let finding = super::super::tests::finding_for_test(file.clone(), 1, 1);
        let identity = EntryIdentity::capture(&file).unwrap();
        assert_eq!(
            assess_source(&finding, &identity).unwrap_err(),
            "sealed staging currently supports directories only"
        );

        let finding = super::super::tests::finding_for_test(source.clone(), 1, 1);
        let other = temp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let wrong_identity = EntryIdentity::capture(&other).unwrap();
        assert_eq!(
            assess_source(&finding, &wrong_identity).unwrap_err(),
            "clean item identity changed before sealed staging policy checks"
        );
    }

    #[test]
    fn source_policy_does_not_create_state() {
        let (temp, _, finding, identity) = directory_fixture();
        let absent_state = temp.path().join("absent-state");
        let prepared = assess_source(&finding, &identity).unwrap();
        assert!(prepared.canonical_source().is_absolute());
        let error = complete(prepared, absent_state.join("degu/trash")).unwrap_err();
        assert!(error.contains("failed to canonicalize prospective trash parent"));
        assert!(!absent_state.exists());
    }

    #[test]
    fn mount_and_anchor_policy_is_fail_closed() {
        let owner = PathBuf::from("/mount/owner");
        let source_parent = Path::new("/mount/owner/source-parent");
        let trash = Path::new("/mount/owner/trash");
        assert_eq!(
            select_recovery_anchor(
                7,
                8,
                owner.clone(),
                source_parent,
                trash,
                |_| Ok(7),
                |path| Ok(path.to_path_buf()),
            )
            .unwrap_err(),
            "sealed staging requires the source and trash destination on one mount"
        );
        assert_eq!(
            select_recovery_anchor(
                7,
                7,
                PathBuf::from("/mount/source-parent"),
                Path::new("/mount/source-parent"),
                Path::new("/mount/trash"),
                |_| Ok(8),
                |path| Ok(path.to_path_buf()),
            )
            .unwrap_err(),
            "source parent equals the writable mount root and no same-mount recovery ancestor exists"
        );
    }

    #[test]
    fn confinement_accepts_only_anchor_or_normal_descendants() {
        let anchor = Path::new("/mount-root");
        assert_eq!(confined_relative(anchor, anchor).unwrap(), PathBuf::new());
        assert_eq!(
            confined_relative(anchor, &anchor.join(".degu-trash")).unwrap(),
            PathBuf::from(".degu-trash")
        );
        assert!(confined_relative(anchor, Path::new("/other/trash")).is_err());
        assert!(confined_relative(anchor, &anchor.join("child/../escape")).is_err());
    }
}
