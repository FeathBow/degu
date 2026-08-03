use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

const RATIONALE: &str = "ModelScope model and dataset cache; repository metadata, temporary downloads, and locks are coordinated by ModelScope, so degu reports the cache without cleaning it. Re-download can be costly; relocate future downloads with MODELSCOPE_CACHE";

/// ModelScope resolves `MODELSCOPE_CACHE` with `os.path.expanduser`, so a value
/// whose first path component is `~` is rooted at the user's home. Operating on
/// path components (not a UTF-8 prefix) keeps `~//x` inside home and preserves
/// non-UTF-8 bytes; `~user` and plain relative paths are left for the
/// absolute-root guard to reject.
fn expand_current_user_home(home: &Path, raw: &OsStr) -> PathBuf {
    let path = PathBuf::from(raw);
    let mut components = path.components();
    if let Some(Component::Normal(first)) = components.next()
        && first == OsStr::new("~")
    {
        return home.join(components.as_path());
    }
    path
}

pub struct Modelscope;

impl Ecosystem for Modelscope {
    fn id(&self) -> &'static str {
        "modelscope"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            ctx.env("MODELSCOPE_CACHE")
                .map(|dir| {
                    Root::redirect("MODELSCOPE_CACHE", expand_current_user_home(&ctx.home, dir))
                })
                .unwrap_or_else(|| Root::well_known(ctx.home.join(".cache/modelscope/hub"))),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "MODELSCOPE_CACHE",
            subdir: "modelscope",
            role: None,
        }]
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (
            Recovery::Regenerable {
                cost: RegenCost::Costly,
            },
            Ownership::ToolCoordinated,
            None,
        )
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::ModelCache,
                facts: self.stated_facts(root),
                rationale: RATIONALE,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::expand_current_user_home;
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    #[test]
    fn tilde_forms_resolve_against_home_without_escaping() {
        let home = Path::new("/home/u");
        assert_eq!(
            expand_current_user_home(home, OsStr::new("~/scratch/ms")),
            PathBuf::from("/home/u/scratch/ms")
        );
        // `~//scratch/ms` must collapse inside home, not reset to an absolute path.
        assert_eq!(
            expand_current_user_home(home, OsStr::new("~//scratch/ms")),
            PathBuf::from("/home/u/scratch/ms")
        );
        assert_eq!(
            expand_current_user_home(home, OsStr::new("~")),
            PathBuf::from("/home/u")
        );
        // `~user` and plain relative paths are left for the absolute-root guard.
        assert_eq!(
            expand_current_user_home(home, OsStr::new("~other/x")),
            PathBuf::from("~other/x")
        );
        assert_eq!(
            expand_current_user_home(home, OsStr::new("relative/x")),
            PathBuf::from("relative/x")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_tilde_suffix_is_expanded() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let home = Path::new("/home/u");
        let raw = OsString::from_vec(b"~/scratch/\xff-cache".to_vec());
        let mut expected = PathBuf::from("/home/u/scratch");
        expected.push(OsStr::from_bytes(b"\xff-cache"));
        assert_eq!(expand_current_user_home(home, &raw), expected);
    }
}
