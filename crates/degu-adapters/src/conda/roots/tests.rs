use super::*;
use std::time::Instant;

#[cfg(unix)]
#[test]
fn expired_deadline_stops_before_children_enumeration() {
    let root = tempfile::tempdir().unwrap();
    let unreadable = root.path().join("loop");
    std::os::unix::fs::symlink("loop", &unreadable).unwrap();
    let ctx = DetectCtx::from_process()
        .unwrap()
        .with_deadline(Some(Instant::now()));
    let mut envs = EnvironmentRoots::default();

    envs.push_children(&ctx, Root::well_known(unreadable));

    assert!(envs.truncated);
    assert!(!envs.incomplete);
    assert!(envs.roots.is_empty());
}

fn fake_ctx(home: &Path) -> DetectCtx {
    let mut ctx = DetectCtx::from_process().unwrap();
    ctx.home = home.to_path_buf();
    ctx
}

/// The marker triad a corroborated base carries: `conda-meta/`, `pkgs/`, and
/// conda's `pkgs/urls.txt`.
fn write_base_markers(base: &Path) {
    std::fs::create_dir_all(base.join("conda-meta")).unwrap();
    std::fs::create_dir_all(base.join("pkgs")).unwrap();
    std::fs::write(
        base.join("pkgs/urls.txt"),
        "https://conda.anaconda.org/conda-forge/noarch\n",
    )
    .unwrap();
}

fn register_environments(home: &Path, entries: &[&Path]) {
    std::fs::create_dir_all(home.join(".conda")).unwrap();
    let text = entries
        .iter()
        .map(|entry| format!("{}\n", entry.display()))
        .collect::<String>();
    std::fs::write(home.join(".conda/environments.txt"), text).unwrap();
}

fn registered_environments(ctx: &DetectCtx) -> Vec<Root> {
    let mut envs = EnvironmentRoots::default();
    push_registered_environments(ctx, &mut envs);
    let outcome = envs.finish();
    assert!(!outcome.incomplete);
    assert!(!outcome.truncated);
    outcome.roots
}

// The field-forensics Caskroom shape: the base lives outside HOME and only
// its child environment is registered, so the grandparent nomination is the
// sole route to the multi-GiB pkgs cache.
#[test]
fn registered_environment_derives_the_pkgs_root_of_its_external_base() {
    let external = tempfile::tempdir().unwrap();
    let base = external
        .path()
        .canonicalize()
        .unwrap()
        .join("Caskroom/miniforge/base");
    write_base_markers(&base);
    let environment = base.join("envs/foo");
    std::fs::create_dir_all(environment.join("conda-meta")).unwrap();
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    register_environments(&home_path, &[&environment]);
    let ctx = fake_ctx(&home_path);
    let environments = registered_environments(&ctx);
    assert_eq!(environments.len(), 1);

    let derived = derive_package_roots(&ctx, &environments);

    assert!(!derived.incomplete);
    assert!(!derived.truncated);
    assert_eq!(derived.roots.len(), 1);
    assert_eq!(derived.roots[0].path, base.join("pkgs"));
    assert_eq!(derived.roots[0].provenance, RootProvenance::WellKnown);
    assert_eq!(derived.roots[0].role, None);
}

// A root environment registers its own prefix in environments.txt, so
// self-nomination alone must reach the pkgs cache.
#[test]
fn registered_base_environment_derives_its_own_pkgs_root() {
    let external = tempfile::tempdir().unwrap();
    let base = external.path().canonicalize().unwrap().join("base");
    write_base_markers(&base);
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    register_environments(&home_path, &[&base]);
    let ctx = fake_ctx(&home_path);
    let environments = registered_environments(&ctx);
    assert_eq!(environments.len(), 1);

    let derived = derive_package_roots(&ctx, &environments);

    assert!(!derived.incomplete);
    assert!(!derived.truncated);
    assert_eq!(derived.roots.len(), 1);
    assert_eq!(derived.roots[0].path, base.join("pkgs"));
}

// A standalone `--prefix` environment has no conda-created base shape: its
// parent is not `envs`, so only the fruitless self-nomination runs.
#[test]
fn standalone_prefix_environment_derives_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let environment = dir.path().canonicalize().unwrap().join("place/myenv");
    std::fs::create_dir_all(environment.join("conda-meta")).unwrap();
    let ctx = DetectCtx::from_process().unwrap();

    let derived = derive_package_roots(&ctx, &[Root::well_known(environment)]);

    assert!(derived.roots.is_empty());
    assert!(!derived.incomplete);
    assert!(!derived.truncated);
}

// A base that looks right but lacks conda's own urls.txt is a look-alike:
// the definitive miss discards the nomination without failing closed.
#[test]
fn base_without_urls_txt_derives_nothing_and_stays_complete() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap().join("base");
    std::fs::create_dir_all(base.join("conda-meta")).unwrap();
    std::fs::create_dir_all(base.join("pkgs")).unwrap();
    let ctx = DetectCtx::from_process().unwrap();

    let derived = derive_package_roots(&ctx, &[Root::well_known(base)]);

    assert!(derived.roots.is_empty());
    assert!(!derived.incomplete);
    assert!(!derived.truncated);
}

// An unreadable pkgs makes the urls.txt probe indeterminate: derivation must
// both refuse the root and fail closed.
#[cfg(unix)]
#[test]
fn unreadable_pkgs_probe_fails_closed_as_incomplete() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap().join("base");
    write_base_markers(&base);
    let pkgs = base.join("pkgs");
    std::fs::set_permissions(&pkgs, std::fs::Permissions::from_mode(0o000)).unwrap();
    let ctx = DetectCtx::from_process().unwrap();

    let derived = derive_package_roots(&ctx, &[Root::well_known(base)]);
    std::fs::set_permissions(&pkgs, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(derived.roots.is_empty());
    assert!(derived.incomplete);
    assert!(!derived.truncated);
}

// A base visible to both the fixed list and a registered environment must
// converge to one root, even when HOME reaches it through a symlink and the
// two spellings differ.
#[cfg(unix)]
#[test]
fn fixed_list_and_derivation_converge_on_one_pkgs_root() {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().canonicalize().unwrap();
    let real_home = dir_path.join("real-home");
    let base = real_home.join("miniconda3");
    write_base_markers(&base);
    let environment = base.join("envs/myenv");
    std::fs::create_dir_all(environment.join("conda-meta")).unwrap();
    let linked_home = dir_path.join("home");
    std::os::unix::fs::symlink(&real_home, &linked_home).unwrap();
    register_environments(&linked_home, &[&environment]);
    let ctx = fake_ctx(&linked_home);
    let environments = registered_environments(&ctx);
    assert_eq!(environments.len(), 1);

    let outcome = well_known_package_roots(&ctx, &environments);

    assert!(!outcome.incomplete);
    assert!(!outcome.truncated);
    assert_eq!(outcome.roots.len(), 1);
    assert_eq!(outcome.roots[0].path, linked_home.join("miniconda3/pkgs"));
}

// Redirect-provenance environments (CONDA_ENVS_PATH/DIRS) never nominate,
// even when their base would corroborate.
#[test]
fn redirect_environment_nominates_nothing() {
    let external = tempfile::tempdir().unwrap();
    let base = external.path().canonicalize().unwrap().join("base");
    write_base_markers(&base);
    let environment = base.join("envs/foo");
    std::fs::create_dir_all(environment.join("conda-meta")).unwrap();
    let ctx = DetectCtx::from_process().unwrap();

    let derived = derive_package_roots(&ctx, &[Root::redirect("CONDA_ENVS_PATH", environment)]);

    assert!(derived.roots.is_empty());
    assert!(!derived.incomplete);
    assert!(!derived.truncated);
}
