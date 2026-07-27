use super::*;

#[test]
fn rejects_inside_protected() {
    let home = tempfile::tempdir().unwrap();
    let key = home.path().join(".ssh/id_rsa");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(&key, []).unwrap();

    let guard = Guard::with_defaults(home.path()).unwrap();
    assert!(guard.check(&key).is_err());
}

#[test]
fn rejects_credential_dirs() {
    let home = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();
    for dir in [".aws", ".kube", ".docker"] {
        let credential = home.path().join(dir).join("config");
        std::fs::create_dir_all(&credential).unwrap();
        assert!(guard.check(&credential).is_err(), "{dir} must be protected");
    }
}

#[test]
fn rejects_ai_tool_state_homes_and_descendants() {
    let home = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();
    for name in MIXED_STATE_AI_TOOL_DIR_NAMES {
        assert_protected_tree(&guard, &home.path().join(name), name);
        assert_protected_tree(&guard, &external.path().join(name), name);
    }
}

#[test]
fn rejects_ancestors_containing_ai_tool_state_directories() {
    let home = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();
    for name in MIXED_STATE_AI_TOOL_DIR_NAMES {
        let external = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(external.path().join("cache").join(name)).unwrap();
        assert!(guard.check(external.path()).is_err(), "{name}");
    }
}

#[test]
fn rejects_ancestors_containing_credential_directories() {
    let home = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();
    for name in CREDENTIAL_DIR_NAMES {
        let external = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(external.path().join("cache").join(name)).unwrap();
        assert!(guard.check(external.path()).is_err(), "{name}");
    }
}

fn assert_protected_tree(guard: &Guard, root: &Path, name: &str) {
    let cache = root.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    for candidate in [root, cache.as_path()] {
        assert!(
            matches!(
                guard.check(candidate),
                Err(GuardError::Protected { protected, .. })
                    if protected.file_name() == Some(OsStr::new(name))
            ),
            "{} must be protected",
            candidate.display()
        );
    }
}

#[test]
fn rejects_ancestor_of_protected() {
    let home = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();
    assert!(guard.check(home.path()).is_err());
}

#[test]
fn rejects_relative() {
    let home = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();
    assert!(guard.check(Path::new(".cache/pip")).is_err());
}

#[test]
fn allows_normal_cache_and_non_sensitive_local_data() {
    let home = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();
    for cache in [
        home.path().join(".cache/pip"),
        home.path().join(".local/share/example-cache"),
        home.path().join(".claude-cache"),
    ] {
        std::fs::create_dir_all(&cache).unwrap();
        assert!(guard.check(&cache).is_ok(), "{}", cache.display());
    }
}

#[test]
fn rejects_sacred_names_outside_home() {
    let home = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();

    for name in CREDENTIAL_DIR_NAMES {
        assert_protected_tree(&guard, &tmp.path().join("x").join(name), name);
    }
}

#[test]
fn allows_non_home_candidate_without_sacred_component() {
    let home = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("x/pipcache");
    std::fs::create_dir_all(&cache).unwrap();

    let guard = Guard::with_defaults(home.path()).unwrap();
    assert!(guard.check(&cache).is_ok());
}

#[test]
fn allows_sacred_name_substring_outside_home() {
    let home = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("x/.sshfoo");
    std::fs::create_dir_all(&cache).unwrap();

    let guard = Guard::with_defaults(home.path()).unwrap();
    assert!(guard.check(&cache).is_ok());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_spelling_both_directions() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    let link = tmp.path().join("link");
    let protected = real.join("protected");
    let candidate = protected.join("cache");
    std::fs::create_dir_all(&candidate).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let mut guard = empty_guard();
    guard.add(link.join("protected")).unwrap();
    assert!(guard.check(&candidate).is_err());

    let mut guard = empty_guard();
    guard.add(protected).unwrap();
    assert!(guard.check(&link.join("protected/cache")).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_ai_tool_state_home_through_symlink_target() {
    let home = tempfile::tempdir().unwrap();
    let real = tempfile::tempdir().unwrap();
    let state = real.path().join("state");
    let cache = state.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::os::unix::fs::symlink(&state, home.path().join(".claude")).unwrap();

    let guard = Guard::with_defaults(home.path()).unwrap();
    assert!(guard.check(&cache).is_err());
    assert!(guard.check(real.path()).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_external_ai_tool_symlink_spelling() {
    let home = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let alias = external.path().join(".codex");
    std::os::unix::fs::symlink(target.path(), &alias).unwrap();

    let guard = Guard::with_defaults(home.path()).unwrap();
    assert!(guard.check(&alias).is_err());
}

fn empty_guard() -> Guard {
    Guard {
        policy: ProtectionPolicy {
            protected_paths: Vec::new(),
            protected_names: Vec::new(),
            recursive_names: Vec::new(),
        },
    }
}

#[test]
fn candidate_canonicalization_failure_is_an_error() {
    let home = tempfile::tempdir().unwrap();
    let guard = Guard::with_defaults(home.path()).unwrap();

    assert!(matches!(
        guard.check(&home.path().join(".cache/missing")),
        Err(GuardError::CandidateCanonicalize { .. })
    ));
}

// Renderers that walk the source chain print the io error themselves, so
// repeating it in the display string would double it.
#[test]
fn io_backed_guard_errors_keep_the_source_out_of_their_display() {
    let io_error = || std::io::Error::from_raw_os_error(2);
    let errors = [
        protected_canonicalize(PathBuf::from("/degu-test"), io_error()),
        candidate_inspect(PathBuf::from("/degu-test"), io_error()),
        GuardError::CandidateCanonicalize {
            path: PathBuf::from("/degu-test"),
            source: io_error(),
        },
    ];
    for error in errors {
        let source = std::error::Error::source(&error)
            .expect("io-backed guard errors must keep their source chain")
            .to_string();
        assert!(
            !error.to_string().contains(&source),
            "display repeats its source: {error}"
        );
    }
}
