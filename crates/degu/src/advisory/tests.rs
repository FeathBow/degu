use super::*;
use degu_core::finding::{
    FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost, finalize_findings,
};

fn finding(path: &str, recovery: Recovery, ownership: Ownership) -> Finding {
    finalize_findings(
        vec![FindingCandidate {
            ecosystem: "test".to_owned(),
            path: PathBuf::from(path),
            kind: FindingKind::PackageCache,
            bytes_apparent: 4096,
            bytes_allocated: 4096,
            age_days: Some(30),
            bytes_hardlinked: 0,
            inodes: 1,
            skipped: 0,
            truncated: false,
            unvisited_dirs: 0,
            shared_writable_dirs: 0,
            parent_grants_foreign_mutation: false,
            protected_boundaries: 0,
            protected_credential_boundaries: 0,
            recovery,
            ownership,
            hazard: None,
            rationale: "fixture".to_owned(),
        }],
        FindingSource::WellKnownRoot,
    )
    .pop()
    .expect("one finalized finding")
}

/// degu does not know what this data is.
fn unknown_recovery(path: &str) -> Finding {
    finding(path, Recovery::Unknown, Ownership::Standalone)
}

/// degu knows what the data is but not who coordinates it. Also a thing
/// degu could not settle, and also worth asking about.
fn unknown_ownership(path: &str) -> Finding {
    finding(
        path,
        Recovery::Regenerable {
            cost: RegenCost::Cheap,
        },
        Ownership::Unknown,
    )
}

/// degu settled this one against cleaning it. Nothing to ask.
fn user_asset(path: &str) -> Finding {
    finding(path, Recovery::UserAsset, Ownership::Standalone)
}

fn eligible(path: &str) -> Finding {
    finding(
        path,
        Recovery::Regenerable {
            cost: RegenCost::Cheap,
        },
        Ownership::Standalone,
    )
}

fn home() -> PathBuf {
    PathBuf::from("/home/account")
}

fn answer(body: &'static str) -> Runner {
    // A fn pointer cannot capture, so each canned answer is its own fn.
    match body {
        "ok" => {
            |_, _, _| {
                Ok(br#"{"advice":[{"id":"0","summary":"a build cache","check":"tool cache dir"}]}"#.to_vec())
            }
        }
        "wrong-id" => {
            |_, _, _| Ok(br#"{"advice":[{"id":"99","summary":"about nothing"}]}"#.to_vec())
        }
        "empty-summary" => |_, _, _| Ok(br#"{"advice":[{"id":"0","summary":"   "}]}"#.to_vec()),
        "garbage" => |_, _, _| Ok(b"not json at all".to_vec()),
        "escapes" => {
            |_, _, _| {
                Ok(b"{\"advice\":[{\"id\":\"0\",\"summary\":\"a\\u001b[31mred\\u001b[0m cache\"}]}".to_vec())
            }
        }
        "fails" => |_, _, _| Err("the advisor exceeded its bound".to_owned()),
        other => panic!("no canned answer {other}"),
    }
}

use super::discovery::CONVENTION_NAME;
use super::protocol::{MAX_SUBJECTS, MAX_SUMMARY_CHARS, bounded};

mod discovery;
mod protocol;

fn context(home: &Path, config_home: &Path) -> DetectCtx {
    DetectCtx::for_test(
        home.to_path_buf(),
        [(
            "XDG_CONFIG_HOME".to_owned(),
            config_home.as_os_str().to_owned(),
        )],
    )
}
