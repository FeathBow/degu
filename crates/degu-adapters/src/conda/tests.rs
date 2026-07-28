use super::roots::EnvironmentRoots;
use super::*;
use std::time::Instant;

#[test]
fn discovered_environment_cannot_be_downgraded_during_scan() {
    let dir = tempfile::tempdir().unwrap();
    let environment = dir.path().join("env");
    std::fs::create_dir_all(environment.join("conda-meta")).unwrap();
    let mut roots = EnvironmentRoots::default();
    let ctx = DetectCtx::from_process().unwrap();
    roots.push(&ctx, Root::well_known(environment.clone()));
    let root = roots.roots.pop().unwrap();
    std::fs::rename(
        environment.join("conda-meta"),
        dir.path().join("detached-meta"),
    )
    .unwrap();

    let outcome = Conda.scan(&root, &ctx);

    assert_eq!(outcome.candidates.len(), 1);
    assert_eq!(outcome.candidates[0].kind, FindingKind::Environment);
    assert_eq!(outcome.candidates[0].recovery, Recovery::UserAsset);
    assert!(outcome.incomplete);
}

#[test]
fn expired_deadline_stops_environment_metadata_probe() {
    let missing = tempfile::tempdir().unwrap().path().join("missing");
    let stats = degu_walk::WalkStats::default();
    let ctx = DetectCtx::from_process()
        .unwrap()
        .with_deadline(Some(Instant::now()));
    let root = Root::well_known(missing.clone()).with_role(ROLE_ENVIRONMENT);

    let (candidate, metadata) =
        environment_candidate(&missing, &stats, &ctx, Conda.stated_facts(&root));

    assert!(!candidate.truncated);
    assert!(metadata.truncated);
    assert!(!metadata.incomplete);
    assert_eq!(candidate.age_days, None);
}
