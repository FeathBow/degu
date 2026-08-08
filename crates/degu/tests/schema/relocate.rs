use super::support::*;

#[test]
fn relocate_json_schema_is_frozen() {
    let home = tempfile::tempdir().unwrap();
    let cache_home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cache_home.path().join("uv")).unwrap();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("XDG_CACHE_HOME", cache_home.path())
            .args(["relocate", "/scratch/x", "--json"])
            .output()
            .unwrap(),
    );

    assert_keys(&json, RELOCATE_REPORT_KEYS);
    let exports = assert_non_empty_array(&json["exports"], "relocate exports");
    for export in exports {
        assert_keys(export, RELOCATE_EXPORT_KEYS);
    }
    assert!(
        exports
            .iter()
            .any(|export| !export["current"].as_array().unwrap().is_empty())
    );
    for entry in assert_non_empty_array(&json["not_relocatable"], "relocate not_relocatable") {
        assert_keys(entry, RELOCATE_NOT_RELOCATABLE_KEYS);
    }
}

#[test]
fn relocate_init_json_schema_is_frozen() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = scratch.path().join("cache");
    let run = || {
        json_stdout(
            degu()
                .env("HOME", home.path())
                .args(["relocate", "--init", "--json"])
                .arg(&target)
                .output()
                .unwrap(),
        )
    };

    let first = run();
    assert_keys(&first, RELOCATE_INIT_REPORT_KEYS);
    assert_keys(&first["initialization"], RELOCATE_INITIALIZATION_KEYS);
    for entry in
        assert_non_empty_array(&first["initialization"]["initialized"], "initialized roots")
    {
        assert!(entry.is_string(), "initialized entry must be a path string");
    }
    assert!(
        first["initialization"]["already_initialized"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let second = run();
    assert_keys(&second, RELOCATE_INIT_REPORT_KEYS);
    assert_keys(&second["initialization"], RELOCATE_INITIALIZATION_KEYS);
    assert!(
        second["initialization"]["initialized"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for entry in assert_non_empty_array(
        &second["initialization"]["already_initialized"],
        "already-initialized roots",
    ) {
        assert!(
            entry.is_string(),
            "already_initialized entry must be a path string"
        );
    }
}
