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
