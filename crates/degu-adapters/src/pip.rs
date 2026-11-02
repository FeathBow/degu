use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::{Path, PathBuf};

pub struct Pip;

/// The directories pip fans out by hash, with the width of the hex names directly
/// beneath each: `http` and `http-v2` start at one character, `wheels` at two.
const HASHED_DIRS: [(&str, usize); 3] = [("http", 1), ("http-v2", 1), ("wheels", 2)];
/// More than any cache's version-check records; a longer listing is not one.
const MAX_SELFCHECK_ENTRIES: usize = 1024;

impl Ecosystem for Pip {
    fn id(&self) -> &'static str {
        "pip"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let mut candidates = Vec::new();
        if let Some(dir) = ctx.env("PIP_CACHE_DIR") {
            candidates.push(Root::redirect("PIP_CACHE_DIR", PathBuf::from(dir)));
        } else {
            candidates.push(crate::xdg_cache_or_platform(ctx, "pip"));
        }
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    /// `PIP_CACHE_DIR` on scratch is how clusters keep pip out of a small home, and
    /// pip writes no `CACHEDIR.TAG` of its own.
    fn matches_redirect_layout(&self, path: &Path) -> bool {
        has_pip_layout(path)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "PIP_CACHE_DIR",
            subdir: "pip",
            role: None,
        }]
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (
            Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            Ownership::Standalone,
            None,
        )
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::PackageCache,
                facts: self.stated_facts(root),
                rationale: "pip download cache; rebuilt automatically on next install, installed environments unaffected",
            },
        )
    }
}

/// Whether `root` looks like pip's cache from its top two levels: every entry is a
/// name pip writes, with the right type, fan-out directories hold hash-shaped names,
/// and at least one cache directory is there. A stray top-level file refuses, so a
/// redirect aimed at most homes and projects stays out. This reads no contents and
/// looks no deeper, so `wheels/ab/results.csv` passes: a match is a reason to ask,
/// never a proof the data can be rebuilt. Any I/O error refuses.
fn has_pip_layout(root: &Path) -> bool {
    if !std::fs::symlink_metadata(root).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    let mut saw_cache = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let Ok(kind) = entry.file_type() else {
            return false;
        };
        let name = entry.file_name();
        let width = HASHED_DIRS
            .iter()
            .find(|(dir, _)| name == *dir)
            .map(|(_, width)| *width);
        let admitted = if let Some(width) = width {
            saw_cache = true;
            kind.is_dir() && has_hashed_children(&entry.path(), width)
        } else if name == "selfcheck" {
            kind.is_dir() && has_only_files(&entry.path())
        } else {
            name == "selfcheck.json" && kind.is_file()
        };
        if !admitted {
            return false;
        }
    }
    saw_cache
}

/// Every child is a directory with a lowercase hex name of exactly `width`.
fn has_hashed_children(dir: &Path, width: usize) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.into_iter().all(|entry| {
        entry.is_ok_and(|entry| {
            let name = entry.file_name();
            let bytes = name.as_encoded_bytes();
            bytes.len() == width
                && bytes
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                && entry.file_type().is_ok_and(|kind| kind.is_dir())
        })
    })
}

fn has_only_files(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut seen = 0;
    for entry in entries {
        seen += 1;
        if seen > MAX_SELFCHECK_ENTRIES
            || !entry.is_ok_and(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(root: &Path, relative: &str) {
        std::fs::create_dir_all(root.join(relative)).unwrap();
    }

    fn file(root: &Path, relative: &str) {
        std::fs::write(root.join(relative), b"x").unwrap();
    }

    /// What a real cache holds: the shape recorded from pip on a cluster.
    fn real_cache() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        dir(root.path(), "http/0/1/2/3/4");
        file(root.path(), "http/0/1/2/3/4/entry");
        dir(root.path(), "http-v2/a/b/c/d/e");
        file(root.path(), "http-v2/a/b/c/d/e/entry.body");
        dir(root.path(), "wheels/0f/1a/2b/rest");
        file(root.path(), "wheels/0f/1a/2b/rest/pkg-1.0-py3-none-any.whl");
        dir(root.path(), "selfcheck");
        file(
            root.path(),
            "selfcheck/117cf651f8fc99a9fd0e81a39d6f9674106803ae520c91674e66b9a4",
        );
        root
    }

    #[test]
    fn real_layout_passes() {
        assert!(has_pip_layout(real_cache().path()));
    }

    // The limit of the check, pinned so nothing leans on it for more: data below the
    // levels it looks at passes, which is why a match only ever earns a review.
    #[test]
    fn deep_user_data_passes() {
        let nested = tempfile::tempdir().unwrap();
        dir(nested.path(), "wheels/ab");
        file(nested.path(), "wheels/ab/results.csv");
        assert!(has_pip_layout(nested.path()));

        let notes = tempfile::tempdir().unwrap();
        dir(notes.path(), "http");
        dir(notes.path(), "selfcheck");
        file(notes.path(), "selfcheck/notes.txt");
        assert!(has_pip_layout(notes.path()));
    }

    #[test]
    fn partial_caches_pass() {
        for cached in ["http", "http-v2", "wheels"] {
            let root = tempfile::tempdir().unwrap();
            dir(root.path(), cached);
            assert!(has_pip_layout(root.path()), "{cached}");
        }
        let old = tempfile::tempdir().unwrap();
        dir(old.path(), "wheels");
        file(old.path(), "selfcheck.json");
        assert!(has_pip_layout(old.path()));
    }

    #[test]
    fn redirect_at_home_refuses() {
        let root = real_cache();
        file(root.path(), ".bashrc");
        dir(root.path(), ".ssh");
        assert!(!has_pip_layout(root.path()));
    }

    #[test]
    fn redirect_at_project_refuses() {
        let root = tempfile::tempdir().unwrap();
        dir(root.path(), "src");
        file(root.path(), "pyproject.toml");
        dir(root.path(), "wheels");
        assert!(!has_pip_layout(root.path()));
    }

    #[test]
    fn empty_directory_refuses() {
        assert!(!has_pip_layout(tempfile::tempdir().unwrap().path()));
    }

    #[test]
    fn missing_directory_refuses() {
        let root = tempfile::tempdir().unwrap();
        assert!(!has_pip_layout(&root.path().join("absent")));
    }

    // One stray file is enough: it is the user's, and a clean would take it along.
    #[test]
    fn mixed_directory_refuses() {
        let root = real_cache();
        file(root.path(), "notes.txt");
        assert!(!has_pip_layout(root.path()));
    }

    #[test]
    fn selfcheck_alone_refuses() {
        let root = tempfile::tempdir().unwrap();
        dir(root.path(), "selfcheck");
        file(root.path(), "selfcheck.json");
        assert!(!has_pip_layout(root.path()));
    }

    // A hand-kept wheelhouse is the near miss: right name, wrong contents.
    #[test]
    fn wheelhouse_refuses() {
        let root = tempfile::tempdir().unwrap();
        dir(root.path(), "wheels");
        file(root.path(), "wheels/torch-2.1-cp311.whl");
        assert!(!has_pip_layout(root.path()));

        let named = tempfile::tempdir().unwrap();
        dir(named.path(), "wheels/release-1.0");
        assert!(!has_pip_layout(named.path()));
    }

    #[test]
    fn wrong_fan_out_refuses() {
        for bad in [
            "http/ab",
            "http/G",
            "http/A",
            "http-v2/00",
            "wheels/0",
            "wheels/abc",
        ] {
            let root = tempfile::tempdir().unwrap();
            dir(root.path(), bad);
            assert!(!has_pip_layout(root.path()), "{bad}");
        }
    }

    #[test]
    fn wrong_types_refuse() {
        let file_for_dir = tempfile::tempdir().unwrap();
        file(file_for_dir.path(), "http");
        assert!(!has_pip_layout(file_for_dir.path()));

        let dir_for_file = real_cache();
        dir(dir_for_file.path(), "selfcheck.json");
        assert!(!has_pip_layout(dir_for_file.path()));

        let nested = real_cache();
        dir(nested.path(), "selfcheck/nested");
        assert!(!has_pip_layout(nested.path()));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_refuse() {
        let target = real_cache();
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("cache");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        assert!(!has_pip_layout(&link), "the redirect root itself");

        let inner = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path().join("http"), inner.path().join("http")).unwrap();
        assert!(!has_pip_layout(inner.path()), "a known name");

        let fan = tempfile::tempdir().unwrap();
        dir(fan.path(), "wheels");
        std::os::unix::fs::symlink(target.path(), fan.path().join("wheels/ab")).unwrap();
        assert!(!has_pip_layout(fan.path()), "a fan-out entry");
    }

    #[test]
    fn too_many_selfchecks_refuse() {
        let root = tempfile::tempdir().unwrap();
        dir(root.path(), "wheels");
        dir(root.path(), "selfcheck");
        for index in 0..=MAX_SELFCHECK_ENTRIES {
            file(root.path(), &format!("selfcheck/{index}"));
        }
        assert!(!has_pip_layout(root.path()));
    }
}
