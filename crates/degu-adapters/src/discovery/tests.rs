use super::{DiscoveryScope, ProjectSources, ResolvedProjectRoot, discover};

/// Asymmetry pin: an unreadable claimed directory records an incomplete region
/// but loses its finding (the claim is never measured), unlike the cache-adapter
/// side, which keeps a finding with skipped > 0 (degu integration test
/// unreadable_nested_claimed_root_reports_incomplete). Fail-closed either way.
#[cfg(unix)]
#[test]
fn unreadable_claimed_dir_records_a_region_and_drops_the_finding() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("app");
    std::fs::create_dir(&app).unwrap();
    std::fs::write(app.join("package.json"), "{}").unwrap();
    let node_modules = app.join("node_modules");
    std::fs::create_dir(&node_modules).unwrap();
    let region = node_modules.canonicalize().unwrap();
    std::fs::set_permissions(&node_modules, std::fs::Permissions::from_mode(0o000)).unwrap();
    let ctx = degu_core::ecosystem::DetectCtx::from_process().unwrap();
    let roots = vec![
        ResolvedProjectRoot::resolve(root.path())
            .unwrap()
            .validate()
            .unwrap(),
    ];
    let scope = DiscoveryScope {
        claimed_roots: &[],
        dependency_claims: &[],
        sources: ProjectSources::new(true, false),
    };

    let outcome = discover(&roots, scope, &ctx).unwrap();
    std::fs::set_permissions(&node_modules, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(outcome.incomplete);
    assert!(outcome.candidates.is_empty());
    assert!(outcome.incomplete_regions.sample().iter().any(|recorded| {
        recorded.path() == region
            && recorded.cause() == degu_core::ecosystem::RegionCause::Measurement
    }));
}

#[cfg(unix)]
#[test]
fn artifact_probe_failure_marks_incomplete_and_keeps_descending() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    let nested = target.join("__pycache__");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("module.pyc"), [0_u8]).unwrap();
    std::os::unix::fs::symlink("CACHEDIR.TAG", target.join("CACHEDIR.TAG")).unwrap();
    let nested = nested.canonicalize().unwrap();
    let ctx = degu_core::ecosystem::DetectCtx::from_process().unwrap();
    let roots = vec![
        ResolvedProjectRoot::resolve(root.path())
            .unwrap()
            .validate()
            .unwrap(),
    ];
    let scope = DiscoveryScope {
        claimed_roots: &[],
        dependency_claims: &[],
        sources: ProjectSources::new(true, false),
    };

    let outcome = discover(&roots, scope, &ctx).unwrap();

    assert!(outcome.incomplete);
    assert!(
        outcome
            .candidates
            .iter()
            .any(|candidate| candidate.path == nested)
    );
}
