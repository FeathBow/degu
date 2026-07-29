use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str = "spack user cache -- repository indices and misc metadata regenerated on the next spack command; spack config and environments live elsewhere under ~/.spack and are untouched";
const INSTANCE_RATIONALE: &str = "possible spack per-instance cache; its id is not verified against a spack root, so degu reports it for review rather than reclaiming it -- reclaim with spack clean";
const ROLE_INSTANCE: &str = "instance";

pub struct Spack;

impl Ecosystem for Spack {
    fn id(&self) -> &'static str {
        "spack"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let base = ctx
            .env("SPACK_USER_CACHE_PATH")
            .map(|dir| Root::redirect("SPACK_USER_CACHE_PATH", PathBuf::from(dir)))
            .unwrap_or_else(|| Root::well_known(ctx.home.join(".spack")));
        // Spack 1.x moved the misc cache under a per-instance-id child; the id is a
        // dynamic hash, so discover it by listing <base> one level (never recurse).
        let mut candidates = vec![base.clone().join("cache")];
        let mut outcome = RootOutcome::default();
        candidates.extend(instance_caches(ctx, &base, &mut outcome));
        outcome.merge(crate::resolve_existing_roots(ctx, self.id(), candidates));
        outcome
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "SPACK_USER_CACHE_PATH",
            subdir: "spack-cache",
            role: None,
        }]
    }

    fn stated_facts(&self, root: &Root) -> FindingFacts {
        let ownership = if root.role == Some(ROLE_INSTANCE) {
            Ownership::ToolCoordinated
        } else {
            Ownership::Standalone
        };
        (
            Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            ownership,
            None,
        )
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        let rationale = if root.role == Some(ROLE_INSTANCE) {
            INSTANCE_RATIONALE
        } else {
            RATIONALE
        };
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::PackageCache,
                facts: self.stated_facts(root),
                rationale,
            },
        )
    }
}

/// `<base>/<child>/cache` for every immediate subdirectory of `<base>`; a read
/// error marks `outcome` incomplete rather than fabricating the missing ids.
fn instance_caches(ctx: &DetectCtx, base: &Root, outcome: &mut RootOutcome) -> Vec<Root> {
    if ctx.deadline_elapsed() {
        outcome.mark_truncated();
        return Vec::new();
    }
    let entries = match std::fs::read_dir(&base.path) {
        Ok(entries) => entries,
        Err(error) if crate::is_missing_path_error(&error) => return Vec::new(),
        Err(error) => {
            tracing::warn!(base = %base.path.display(), %error, "spack cache base scan failed");
            outcome.mark_incomplete();
            return Vec::new();
        }
    };
    let mut caches = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(base = %base.path.display(), %error, "spack cache base entry failed");
                outcome.mark_incomplete();
                continue;
            }
        };
        let name = entry.file_name();
        // `file_type` does not follow symlinks (unlike `path().is_dir()`), so an
        // id-shaped child symlinked outside ~/.spack is skipped, not promoted.
        if !is_instance_id(&name) {
            continue;
        }
        match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => {
                caches.push(
                    base.clone()
                        .join(&name)
                        .join("cache")
                        .with_role(ROLE_INSTANCE),
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(base = %base.path.display(), %error, "spack cache base entry type failed");
                outcome.mark_incomplete();
            }
        }
    }
    caches
}

/// Spack instance ids are RFC4648 base32, so the digits are `2-7` only.
fn is_instance_id(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|s| s.len() == 7 && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ctx(home: &std::path::Path) -> DetectCtx {
        let mut ctx = DetectCtx::from_process().unwrap();
        ctx.home = home.to_path_buf();
        ctx
    }

    #[test]
    fn roots_discovers_fixed_and_instance_caches() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(".spack");
        std::fs::create_dir_all(base.join("cache")).unwrap();
        std::fs::create_dir_all(base.join("zvq4d7m/cache")).unwrap();
        std::fs::create_dir_all(base.join("ordinary/cache")).unwrap();

        let outcome = Spack.roots(&fake_ctx(home.path()));
        let paths: Vec<_> = outcome.roots.iter().map(|r| r.path.clone()).collect();

        assert!(paths.contains(&base.join("cache")));
        assert!(paths.contains(&base.join("zvq4d7m/cache")));
        assert!(!paths.contains(&base.join("ordinary/cache")));
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn instance_caches_are_report_only_and_fixed_cache_is_eligible() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(".spack");
        std::fs::create_dir_all(base.join("cache")).unwrap();
        // reports/secrets/project are real 7-char base32 words (spack itself uses
        // ~/.spack/reports), so a name match must never grant clean authority.
        for name in ["zvq4d7m", "reports", "secrets", "project"] {
            std::fs::create_dir_all(base.join(name).join("cache")).unwrap();
        }

        let outcome = Spack.roots(&fake_ctx(home.path()));
        assert_eq!(outcome.roots.len(), 5);
        for root in &outcome.roots {
            let ownership = Spack.stated_facts(root).1;
            if root.path == base.join("cache") {
                assert_eq!(ownership, Ownership::Standalone);
            } else {
                assert_eq!(ownership, Ownership::ToolCoordinated);
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn roots_skips_id_shaped_symlink_to_external_cache() {
        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(external.path().join("cache")).unwrap();
        let base = home.path().join(".spack");
        std::fs::create_dir_all(&base).unwrap();
        std::os::unix::fs::symlink(external.path(), base.join("zvq4d7m")).unwrap();

        let outcome = Spack.roots(&fake_ctx(home.path()));
        let paths: Vec<_> = outcome.roots.iter().map(|r| r.path.clone()).collect();

        assert!(!paths.contains(&base.join("zvq4d7m/cache")));
    }

    #[test]
    fn instance_id_accepts_only_base32_lowercase_seven_char_hashes() {
        assert!(is_instance_id(std::ffi::OsStr::new("zvq4d7m")));
        assert!(is_instance_id(std::ffi::OsStr::new("abcde23")));
        assert!(!is_instance_id(std::ffi::OsStr::new("abc0189"))); // 0/1/8/9 outside base32
        assert!(!is_instance_id(std::ffi::OsStr::new("zvq4d7")));
        assert!(!is_instance_id(std::ffi::OsStr::new("zvq4d7ma")));
        assert!(!is_instance_id(std::ffi::OsStr::new("ZVQ4D7M")));
    }
}
