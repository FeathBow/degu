use super::support::*;

#[test]
fn shared_writable_cache_is_measured_but_report_only() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("pip-cache");
    std::fs::create_dir(&cache).unwrap();
    std::fs::write(
        cache.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(cache.join("data.bin"), [1_u8; 32]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o770)).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--json", "--only", "pip"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let finding = &findings.as_array().unwrap()[0];
    assert_eq!(finding["skipped"], 0, "the size remains fully measured");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(
        finding["disposition"]["reason"],
        "path contains a group- or world-writable directory"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn foreign_owned_cache_entry_is_excluded_and_never_cleaned() {
    use std::os::unix::fs::MetadataExt;

    let foreign_source = std::path::Path::new("/etc/hosts");
    let foreign_uid = std::fs::symlink_metadata(foreign_source).unwrap().uid();
    if foreign_uid == rustix::process::geteuid().as_raw() {
        return;
    }

    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("pip-cache");
    std::fs::create_dir(&cache).unwrap();
    std::fs::write(
        cache.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    let foreign_entry = cache.join("foreign-hosts");
    if let Err(error) = std::fs::hard_link(foreign_source, &foreign_entry) {
        eprintln!("platform refused the unprivileged foreign hardlink fixture: {error}");
        return;
    }
    assert_eq!(
        std::fs::symlink_metadata(&foreign_entry).unwrap().uid(),
        foreign_uid
    );
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let scan = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--json", "--only", "pip"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = scan_findings(&scan.stdout);
    let finding = &findings.as_array().unwrap()[0];
    assert_eq!(finding["inodes"], 2, "root and owned CACHEDIR.TAG only");
    assert_eq!(finding["skipped"], 1);
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(
        finding["disposition"]["reason"],
        "measurement incomplete: some paths were not measured"
    );

    let clean = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["clean", "--yes", "--json", "--only", "pip", "--path"])
        .arg(&cache)
        .output()
        .unwrap();

    assert!(
        !clean.status.success(),
        "incomplete selection must fail closed"
    );
    assert!(cache.is_dir());
    assert!(foreign_entry.is_file());
    assert!(!home.path().join(".local/state/degu/trash").exists());
    assert!(!home.path().join(".local/state/degu/ops.jsonl").exists());
}
