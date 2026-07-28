use degu_core::ecosystem::{DetectCtx, Root, RootOrigin, RootOutcome};

pub(crate) fn resolve_existing_roots(
    ctx: &DetectCtx,
    ecosystem: &str,
    candidates: impl IntoIterator<Item = Root>,
) -> RootOutcome {
    let mut outcome = RootOutcome::default();
    let mut candidates = candidates.into_iter();
    loop {
        if ctx.deadline_elapsed() {
            outcome.mark_truncated();
            break;
        }
        let Some(candidate) = candidates.next() else {
            break;
        };
        if !validate_root_path(ctx, ecosystem, &candidate) {
            outcome.mark_incomplete();
            continue;
        }
        if ctx.deadline_elapsed() {
            outcome.mark_truncated();
            break;
        }
        match std::fs::metadata(&candidate.path) {
            Ok(metadata) if metadata.is_dir() => {
                if !outcome.roots.iter().any(|root| root.path == candidate.path) {
                    outcome.roots.push(candidate);
                }
            }
            Ok(_) => {
                tracing::warn!(
                    path = %candidate.path.display(),
                    ecosystem,
                    "cache root is not a directory"
                );
                outcome.mark_incomplete();
            }
            Err(error) if crate::is_missing_path_error(&error) => {}
            Err(error) => {
                tracing::warn!(
                    path = %candidate.path.display(),
                    ecosystem,
                    %error,
                    "cache root probe failed"
                );
                outcome.record_failure(candidate.path, error);
            }
        }
    }
    outcome
}

pub(crate) fn validate_root_path(ctx: &DetectCtx, ecosystem: &str, root: &Root) -> bool {
    if root.path.is_absolute() {
        return true;
    }
    match root.origin {
        RootOrigin::Environment(variable) => {
            if ctx.claim_invalid_root_diagnostic(variable) {
                tracing::warn!(
                    path = %root.path.display(),
                    ecosystem,
                    variable,
                    "environment-derived cache root is not absolute"
                );
            }
        }
        RootOrigin::Fixed => tracing::warn!(
            path = %root.path.display(),
            ecosystem,
            "built-in cache root is not absolute"
        ),
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // A self-symlink (`ln -s ~/.cache/pip ~/.cache/pip` residue) fails the
    // probe with ELOOP; the outcome must carry the path and the error so the
    // CLI refusal can name them.
    #[test]
    fn probe_failure_records_the_failing_path_and_os_error() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("pip");
        std::os::unix::fs::symlink(&cache, &cache).unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        let outcome = resolve_existing_roots(&ctx, "pip", [Root::well_known(cache.clone())]);

        assert!(outcome.incomplete);
        let failure = outcome.failures.first().expect("failure recorded");
        assert_eq!(failure.path, cache);
        assert_eq!(failure.error.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn expired_deadline_stops_before_candidate_probe() {
        let advances = std::cell::Cell::new(0_u64);
        let candidates = std::iter::from_fn(|| {
            advances.set(advances.get().saturating_add(1));
            Some(Root::well_known("/degu-unvisited".into()))
        });
        let ctx = DetectCtx::from_process()
            .unwrap()
            .with_deadline(Some(Instant::now()));

        let outcome = resolve_existing_roots(&ctx, "test", candidates);

        assert!(outcome.truncated);
        assert!(!outcome.incomplete);
        assert!(outcome.roots.is_empty());
        assert_eq!(advances.get(), 0);
    }
}
