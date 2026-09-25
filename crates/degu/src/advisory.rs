//! Decision support beside a finding, never part of one.
//!
//! degu classifies from what it measured. When it cannot classify, the reader is
//! left with a size and a name, which is not enough to decide with and is why
//! the unrecognized tier is where people give up and reach for `rm -rf`.
//!
//! This module fills that gap without putting anything into the decision.
//! degu speaks no model protocol, ships no client, and holds no credential: the
//! reader names an executable, degu hands it a signature on standard input and
//! reads prose back, under the same bounds every other host tool runs under.
//! Which model, which endpoint and which key are that program's business.
//! degu could not learn them if it wanted to — the child's environment is
//! emptied before exec, so a credential cannot be passed through it.
//!
//! Nothing here can reach a disposition, a plan, or a selection. The strongest
//! thing an advisory can do is put a sentence on a screen, and the screen says
//! whose sentence it is.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use degu_core::config::AdvisoryConfig;
use degu_core::finding::Finding;

/// Findings sent in one request. An advisor is consulted about what degu could
/// not name, not about everything it found, so this bounds a request to the
/// largest handful worth asking about.
const MAX_SUBJECTS: usize = 32;

/// A response is a few sentences per subject. This admits a generous answer and
/// refuses a flood.
const RESPONSE_CAP_BYTES: usize = 64 * 1024;

/// Room for a paragraph, not an essay. A pane has to stay readable, and an
/// advisor that writes past this is not answering the question.
const MAX_SUMMARY_CHARS: usize = 600;
const MAX_CHECK_CHARS: usize = 160;

/// What degu tells an advisor about one thing it could not classify.
///
/// A signature carries the shape of a location, never the account it belongs
/// to. Under the account home that is the elided path degu prints everywhere
/// else. Outside it there is no prefix degu can remove and still leave anything
/// meaningful, and an absolute path on a shared filesystem carries the account
/// name inside it — `/scratch/<user>/...` is the ordinary case on the machines
/// degu targets — so only the last component goes, and the subject says the
/// rest was withheld rather than letting an advisor read a truncated path as a
/// whole one.
///
/// Nothing below the named directory is described either: no file list, no
/// contents, no names of the reader's own work.
#[derive(serde::Serialize)]
struct Subject {
    /// The finding this subject was built from, kept so an answer can be put
    /// back where it belongs. Never serialized: `path` is what an advisor is
    /// shown, and that one is anonymized.
    #[serde(skip)]
    target: PathBuf,
    id: String,
    path: String,
    /// The ancestors were not sent, because they could not be anonymized.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    ancestors_withheld: bool,
    name: String,
    ecosystem: String,
    kind: &'static str,
    bytes_allocated: u64,
    inodes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    age_days: Option<u64>,
    measurement_incomplete: bool,
    reason: String,
}

#[derive(serde::Serialize)]
struct Request<'a> {
    degu_advisory_request: u32,
    subjects: &'a [Subject],
}

#[derive(serde::Deserialize)]
struct Response {
    #[serde(default)]
    advice: Vec<ResponseAdvice>,
}

#[derive(serde::Deserialize)]
struct ResponseAdvice {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    check: Option<String>,
}

/// One advisor's answer about one location, already bounded and de-escaped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Advice {
    /// What the advisor thinks this is. Never a classification.
    pub(crate) summary: String,
    /// A command the reader can run to confirm or refute the summary.
    ///
    /// This is the most useful thing an advisor produces: it turns an opinion
    /// into something the reader can settle themselves. An answer without one
    /// stays a hint.
    pub(crate) check: Option<String>,
}

/// Where an advisor is found without any configuration.
///
/// Dropping an executable at `$XDG_CONFIG_HOME/degu/advisor` is the whole
/// setup. An account with no such file consults nobody and sends nothing, which
/// is what an untouched install has to do on a login node; an account that put
/// one there has already answered the question, and answered it knowing what it
/// was for. Asking during setup would take that answer before the reader has
/// ever met the kind of location it is about.
pub(crate) const CONVENTION_NAME: &str = "advisor";

/// How degu found the advisor it is about to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Named by `advisory.command`.
    Configured,
    /// Found at the conventional path, with nothing configured.
    Convention,
}

/// What degu will do about an advisor, decided before one runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    Found {
        path: PathBuf,
        origin: Origin,
    },
    /// Nothing named and nothing at the conventional path.
    Absent {
        convention: PathBuf,
    },
    /// Something is there that degu will not run, and why.
    ///
    /// Never silently skipped: a reader who put a file there meant it to be
    /// used, and one degu declines to exec is a thing they need told.
    Refused {
        path: PathBuf,
        reason: String,
    },
}

/// Decide which advisor to run, if any.
///
/// A configured path wins, because naming one is an explicit choice. The
/// conventional path is consulted only when nothing is named.
pub(crate) fn resolve_advisor(config: &AdvisoryConfig, config_home: &Path) -> Resolution {
    let convention = config_home.join("degu").join(CONVENTION_NAME);
    match config.command.as_deref() {
        Some(command) => admit(PathBuf::from(command), Origin::Configured, &convention),
        None => admit(convention.clone(), Origin::Convention, &convention),
    }
}

/// An advisor runs with this account's privileges, so the question is whether
/// anyone else decides what it does. A file another account can rewrite is one
/// degu would be executing on their behalf.
fn admit(path: PathBuf, origin: Origin, convention: &Path) -> Resolution {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match origin {
                // A named path that is not there is a mistake worth reporting.
                Origin::Configured => Resolution::Refused {
                    path,
                    reason: "nothing exists at this path".to_owned(),
                },
                // An absent convention is the ordinary case, not a mistake.
                Origin::Convention => Resolution::Absent {
                    convention: convention.to_path_buf(),
                },
            };
        }
        Err(error) => {
            return Resolution::Refused {
                path,
                reason: format!("it could not be inspected: {error}"),
            };
        }
    };
    if !metadata.is_file() {
        return Resolution::Refused {
            path,
            reason: "it is not a regular file".to_owned(),
        };
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Resolution::Refused {
            path,
            reason: "it belongs to another account".to_owned(),
        };
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Resolution::Refused {
            path,
            reason: "it is writable by its group or by everyone".to_owned(),
        };
    }
    if mode & 0o100 == 0 {
        return Resolution::Refused {
            path,
            reason: "it is not executable".to_owned(),
        };
    }
    Resolution::Found { path, origin }
}

/// Why a pane has no external advisory to show.
///
/// Distinguished because they mean different things to the reader: one is a
/// choice they have not made, the rest are a program of theirs that did not
/// work. Silence would read as "degu has nothing to say", which is a different
/// and untrue statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// No advisor exists, carrying where one would go.
    Absent(PathBuf),
    /// Something is there that degu declined to run.
    Refused(String),
    /// An advisor ran and produced nothing usable.
    Failed(String),
}

/// Every advisory for one review, keyed by the path it is about.
#[derive(Clone, Debug, Default)]
pub(crate) struct Advisories {
    advice: BTreeMap<PathBuf, Advice>,
    unavailable: Option<Unavailable>,
    /// The program that produced these, for the pane to name.
    source: Option<String>,
    /// The reader turned the pane off. Nothing is drawn at all: turning
    /// something off has to remove it, not change what it says.
    disabled: bool,
}

impl Advisories {
    fn without(unavailable: Unavailable) -> Self {
        Self {
            unavailable: Some(unavailable),
            ..Self::default()
        }
    }

    pub(crate) fn for_path(&self, path: &Path) -> Option<&Advice> {
        self.advice.get(path)
    }

    pub(crate) fn unavailable(&self) -> Option<&Unavailable> {
        self.unavailable.as_ref()
    }

    pub(crate) fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub(crate) fn disabled(&self) -> bool {
        self.disabled
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        advice: impl IntoIterator<Item = (PathBuf, Advice)>,
        unavailable: Option<Unavailable>,
        source: Option<&str>,
    ) -> Self {
        Self {
            advice: advice.into_iter().collect(),
            unavailable,
            source: source.map(str::to_owned),
            disabled: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn disabled_for_test() -> Self {
        Self {
            disabled: true,
            ..Self::default()
        }
    }
}

/// Whether this finding is one degu could not classify.
///
/// Exactly two reasons mean "degu does not know": what the data is, and who
/// coordinates it. `report_only_reason` is the only thing that produces either,
/// so a finding carrying one is Not managed by construction and asking the tier
/// as well would restate that rather than check it.
///
/// Every other withheld finding is already decided — a user asset, a
/// tool-coordinated directory, a credential boundary, a shared-writable parent.
/// Sending those would widen what leaves the machine for an answer that could
/// not change anything.
pub(crate) fn is_unrecognized(finding: &Finding) -> bool {
    matches!(
        finding.disposition().reason.as_deref(),
        Some(degu_core::disposition::UNKNOWN_RECOVERY)
            | Some(degu_core::disposition::UNKNOWN_OWNERSHIP)
    )
}

fn subjects(findings: &[Finding], home: &Path) -> Vec<Subject> {
    let mut chosen: Vec<&Finding> = findings.iter().filter(|f| is_unrecognized(f)).collect();
    // Largest first: a bounded request should spend its room on what the reader
    // is most likely to be looking at.
    chosen.sort_by_key(|finding| std::cmp::Reverse(finding.bytes_allocated()));
    chosen.truncate(MAX_SUBJECTS);
    chosen
        .into_iter()
        .enumerate()
        .map(|(index, finding)| {
            let (path, ancestors_withheld) = named(finding.path(), home);
            Subject {
                target: finding.path().to_path_buf(),
                id: index.to_string(),
                path,
                ancestors_withheld,
                name: finding
                    .path()
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                ecosystem: finding.ecosystem().to_owned(),
                kind: crate::findings::kind_label(finding.kind()),
                bytes_allocated: finding.bytes_allocated(),
                inodes: finding.inodes(),
                age_days: finding.age_days(),
                measurement_incomplete: finding.measurement_incomplete(),
                reason: finding
                    .disposition()
                    .reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            }
        })
        .collect()
}

/// How one location is named to an advisor, and whether its ancestors were
/// dropped to get there.
fn named(path: &Path, home: &Path) -> (String, bool) {
    if path.starts_with(home) {
        return (crate::presentation::display_path(path, home), false);
    }
    let last = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    (last, true)
}

/// Consult the configured advisor about what degu could not classify.
///
/// Every failure is an absence of advice, never an error the reader has to
/// clear: an advisory is decision support, and a review must open whether or not
/// somebody's script worked.
pub(crate) fn consult(
    config: &AdvisoryConfig,
    findings: &[Finding],
    home: &Path,
    config_home: &Path,
) -> Advisories {
    if !config.enabled {
        return Advisories {
            disabled: true,
            ..Advisories::default()
        };
    }
    // Before looking for an advisor at all: a scan where degu classified
    // everything has nothing to ask about, and neither starting somebody's
    // program nor reporting on one they have not set up says anything useful
    // about a screen where no advisory block will be drawn.
    let subjects = subjects(findings, home);
    if subjects.is_empty() {
        return Advisories::default();
    }
    let path = match resolve_advisor(config, config_home) {
        Resolution::Found { path, .. } => path,
        Resolution::Absent { convention } => {
            return Advisories::without(Unavailable::Absent(convention));
        }
        Resolution::Refused { path, reason } => {
            return Advisories::without(Unavailable::Refused(format!(
                "{} was not run because {reason}",
                path.display()
            )));
        }
    };
    let command = path.to_string_lossy().into_owned();
    // What the pane will name. Elided like every other path degu prints, so an
    // advisor under the account home reads as `~/.config/degu/advisor` rather
    // than spending three wrapped lines on the reader's own home.
    let shown = crate::presentation::display_path(&path, home);
    consult_with(
        &command,
        &shown,
        Duration::from_secs(config.timeout_seconds),
        &subjects,
        run_advisor,
    )
}

type Runner = fn(&Path, &[u8], Duration) -> Result<Vec<u8>, String>;

fn run_advisor(binary: &Path, input: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let arguments: [&OsStr; 0] = [];
    match degu_core::system_tool::run_capped_with_input(
        binary,
        &arguments,
        input,
        timeout,
        RESPONSE_CAP_BYTES,
    ) {
        Ok(run) if run.success => Ok(run.stdout),
        Ok(_) => Err("the advisor exited unsuccessfully".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

fn consult_with(
    command: &str,
    shown: &str,
    timeout: Duration,
    subjects: &[Subject],
    run: Runner,
) -> Advisories {
    let request = Request {
        degu_advisory_request: 1,
        subjects,
    };
    let Ok(payload) = serde_json::to_vec(&request) else {
        return failed(shown, "the request could not be encoded");
    };
    let output = match run(Path::new(command), &payload, timeout) {
        Ok(output) => output,
        Err(reason) => return failed(shown, &reason),
    };
    let Ok(response) = serde_json::from_slice::<Response>(&output) else {
        return failed(shown, "the advisor did not answer with a degu advisory");
    };
    Advisories {
        advice: resolve(&response, subjects),
        unavailable: None,
        source: Some(shown.to_owned()),
        disabled: false,
    }
}

/// Map answers back onto the locations degu asked about, never onto paths an
/// advisor names.
///
/// An advisor answers by the id it was given, and the subject carries the
/// finding it was built from, so an answer returns to that location and nowhere
/// else. A path in a response is ignored entirely. Keying this off the name an
/// advisor was shown would not work: that name is anonymized for anything
/// outside the account home, which is the ordinary case on a shared filesystem.
fn resolve(response: &Response, subjects: &[Subject]) -> BTreeMap<PathBuf, Advice> {
    let by_id: BTreeMap<&str, &Subject> = subjects
        .iter()
        .map(|subject| (subject.id.as_str(), subject))
        .collect();
    response
        .advice
        .iter()
        .filter_map(|advice| {
            let subject = by_id.get(advice.id.as_str())?;
            let path = &subject.target;
            let summary = bounded(&advice.summary, MAX_SUMMARY_CHARS);
            if summary.is_empty() {
                return None;
            }
            Some((
                path.clone(),
                Advice {
                    summary,
                    check: advice
                        .check
                        .as_deref()
                        .map(|check| bounded(check, MAX_CHECK_CHARS))
                        .filter(|check| !check.is_empty()),
                },
            ))
        })
        .collect()
}

/// Advisory text is a foreign program's output rendered into a terminal, so it
/// is stripped of anything that could move a cursor or set an attribute before
/// it is ever a `Line`, and bounded before it is ever laid out.
fn bounded(text: &str, limit: usize) -> String {
    let cleaned = crate::presentation::escape_terminal_text(text.trim());
    let mut out = String::new();
    for (index, character) in cleaned.chars().enumerate() {
        if index >= limit {
            out.push('…');
            break;
        }
        out.push(character);
    }
    out
}

fn failed(command: &str, reason: &str) -> Advisories {
    Advisories {
        advice: BTreeMap::new(),
        unavailable: Some(Unavailable::Failed(reason.to_owned())),
        source: Some(command.to_owned()),
        disabled: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use degu_core::finding::{
        FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost,
        finalize_findings,
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
            "ok" => |_, _, _| {
                Ok(br#"{"advice":[{"id":"0","summary":"a build cache","check":"tool cache dir"}]}"#.to_vec())
            },
            "wrong-id" => {
                |_, _, _| Ok(br#"{"advice":[{"id":"99","summary":"about nothing"}]}"#.to_vec())
            }
            "empty-summary" => |_, _, _| Ok(br#"{"advice":[{"id":"0","summary":"   "}]}"#.to_vec()),
            "garbage" => |_, _, _| Ok(b"not json at all".to_vec()),
            "escapes" => |_, _, _| {
                Ok(b"{\"advice\":[{\"id\":\"0\",\"summary\":\"a\\u001b[31mred\\u001b[0m cache\"}]}".to_vec())
            },
            "fails" => |_, _, _| Err("the advisor exceeded its bound".to_owned()),
            other => panic!("no canned answer {other}"),
        }
    }

    /// An advisory is asked for only where degu has no answer. A location it
    /// withheld because it recognized a user asset is already decided, and
    /// sending it would widen what leaves the machine to no purpose.
    #[test]
    fn only_what_degu_could_not_classify_is_sent() {
        let findings = [
            unknown_recovery("/home/account/.cache/mystery"),
            unknown_ownership("/home/account/.cache/shared"),
            user_asset("/home/account/Documents"),
            eligible("/home/account/.cache/pip"),
        ];
        let asked: Vec<String> = subjects(&findings, &home())
            .into_iter()
            .map(|subject| subject.path)
            .collect();
        let sent = |path: &str| asked.iter().any(|asked| asked == path);
        assert!(sent("~/.cache/mystery"), "{asked:?}");
        assert!(sent("~/.cache/shared"), "{asked:?}");
        assert!(!sent("~/Documents"), "a settled user asset was sent");
        assert!(!sent("~/.cache/pip"), "a classified cache was sent");
    }

    /// A cache outside the account home has no prefix degu can remove: on the
    /// machines degu targets the ordinary case is `/scratch/<user>/...`, where
    /// the account name is a path component. Only the last component goes, and
    /// the subject admits the rest was dropped.
    #[test]
    fn a_location_outside_the_home_travels_without_its_ancestors() {
        let findings = [unknown_recovery("/scratch/someuser/weirdcache")];
        let subjects = subjects(&findings, &home());
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0].path, "weirdcache");
        assert!(subjects[0].ancestors_withheld);
        let payload = serde_json::to_string(&Request {
            degu_advisory_request: 1,
            subjects: &subjects,
        })
        .expect("a request encodes");
        assert!(!payload.contains("someuser"), "{payload}");
        assert!(!payload.contains("/scratch"), "{payload}");
    }

    /// Under the home the elided path is already anonymous, so the shape is
    /// kept whole and nothing is claimed to be withheld.
    #[test]
    fn a_location_under_the_home_keeps_its_shape() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let subjects = subjects(&findings, &home());
        assert_eq!(subjects[0].path, "~/.cache/mystery");
        assert!(!subjects[0].ancestors_withheld);
    }

    /// The account home never leaves the machine: a signature carries the shape
    /// of a location, not whose it is.
    #[test]
    fn a_subject_carries_an_elided_path() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let payload = serde_json::to_string(&Request {
            degu_advisory_request: 1,
            subjects: &subjects(&findings, &home()),
        })
        .expect("a request encodes");
        assert!(!payload.contains("/home/account"), "{payload}");
        assert!(payload.contains("~/.cache/mystery"), "{payload}");
    }

    #[test]
    fn an_answer_is_attached_to_the_location_it_was_asked_about() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let subjects = subjects(&findings, &home());
        let advisories = consult_with(
            "/bin/advisor",
            "~/bin/advisor",
            Duration::from_secs(1),
            &subjects,
            answer("ok"),
        );
        let advice = advisories
            .for_path(Path::new("/home/account/.cache/mystery"))
            .expect("advice for the subject");
        assert_eq!(advice.summary, "a build cache");
        assert_eq!(advice.check.as_deref(), Some("tool cache dir"));
        assert_eq!(advisories.unavailable(), None);
    }

    /// The ordinary case on the machines degu targets is a cache outside the
    /// home, whose subject carries only its last component. The answer still has
    /// to reach the location it was asked about.
    #[test]
    fn an_answer_reaches_a_location_outside_the_home() {
        let findings = [unknown_recovery("/scratch/someuser/weirdcache")];
        let subjects = subjects(&findings, &home());
        let advisories = consult_with(
            "/bin/advisor",
            "~/bin/advisor",
            Duration::from_secs(1),
            &subjects,
            answer("ok"),
        );
        assert!(
            advisories
                .for_path(Path::new("/scratch/someuser/weirdcache"))
                .is_some(),
            "advice for a location outside the home was dropped"
        );
    }

    /// An advisor answers by the id it was given. Anything else it names is a
    /// location degu did not ask about, and attaching a sentence there would let
    /// a foreign program speak about a path it was never shown.
    #[test]
    fn an_answer_about_an_id_that_was_not_asked_is_dropped() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let subjects = subjects(&findings, &home());
        let advisories = consult_with(
            "/bin/advisor",
            "~/bin/advisor",
            Duration::from_secs(1),
            &subjects,
            answer("wrong-id"),
        );
        assert!(
            advisories
                .for_path(Path::new("/home/account/.cache/mystery"))
                .is_none()
        );
    }

    #[test]
    fn an_empty_summary_is_not_an_advisory() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let subjects = subjects(&findings, &home());
        let advisories = consult_with(
            "/bin/advisor",
            "~/bin/advisor",
            Duration::from_secs(1),
            &subjects,
            answer("empty-summary"),
        );
        assert!(
            advisories
                .for_path(Path::new("/home/account/.cache/mystery"))
                .is_none()
        );
    }

    /// Advisory text is a foreign program's bytes on their way to a terminal.
    #[test]
    fn advisory_text_cannot_carry_terminal_control() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let subjects = subjects(&findings, &home());
        let advisories = consult_with(
            "/bin/advisor",
            "~/bin/advisor",
            Duration::from_secs(1),
            &subjects,
            answer("escapes"),
        );
        let advice = advisories
            .for_path(Path::new("/home/account/.cache/mystery"))
            .expect("advice");
        assert!(!advice.summary.contains('\u{1b}'), "{}", advice.summary);
    }

    #[test]
    fn a_long_answer_is_bounded() {
        let long = "x".repeat(MAX_SUMMARY_CHARS * 3);
        let bounded = bounded(&long, MAX_SUMMARY_CHARS);
        assert_eq!(bounded.chars().count(), MAX_SUMMARY_CHARS + 1);
        assert!(bounded.ends_with('…'));
    }

    /// Every way an advisor can fail is an absence of advice, never an error the
    /// reader has to clear: the review has to open either way.
    #[test]
    fn a_failing_advisor_is_an_absence_not_an_error() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let subjects = subjects(&findings, &home());
        for canned in ["fails", "garbage"] {
            let advisories = consult_with(
                "/bin/advisor",
                "~/bin/advisor",
                Duration::from_secs(1),
                &subjects,
                answer(canned),
            );
            assert!(
                matches!(advisories.unavailable(), Some(Unavailable::Failed(_))),
                "{canned} did not report a failure"
            );
            assert!(
                advisories
                    .for_path(Path::new("/home/account/.cache/mystery"))
                    .is_none()
            );
        }
    }

    /// An account that has not put a script anywhere consults nobody, and the
    /// pane is told where one would go rather than which key to set.
    #[test]
    fn no_advisor_anywhere_is_reported_as_an_absence() {
        let empty = tempfile::tempdir().expect("a config home");
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let advisories = consult(&AdvisoryConfig::default(), &findings, &home(), empty.path());
        assert_eq!(
            advisories.unavailable(),
            Some(&Unavailable::Absent(
                empty.path().join("degu").join(CONVENTION_NAME)
            ))
        );
    }

    fn executable(directory: &Path, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.join(name);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("a script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("a mode");
        path
    }

    /// Dropping a script at the conventional path is the whole setup. Nothing
    /// is configured here, and degu finds it anyway.
    #[test]
    fn a_script_at_the_conventional_path_needs_no_configuration() {
        let config_home = tempfile::tempdir().expect("a config home");
        let degu = config_home.path().join("degu");
        std::fs::create_dir_all(&degu).expect("the degu config directory");
        let advisor = executable(&degu, CONVENTION_NAME, 0o700);
        assert_eq!(
            resolve_advisor(&AdvisoryConfig::default(), config_home.path()),
            Resolution::Found {
                path: advisor,
                origin: Origin::Convention
            }
        );
    }

    /// Naming one is an explicit choice, so it wins over whatever happens to be
    /// at the conventional path.
    #[test]
    fn a_named_advisor_wins_over_the_convention() {
        let config_home = tempfile::tempdir().expect("a config home");
        let degu = config_home.path().join("degu");
        std::fs::create_dir_all(&degu).expect("the degu config directory");
        executable(&degu, CONVENTION_NAME, 0o700);
        let named = executable(config_home.path(), "chosen", 0o700);
        let config = AdvisoryConfig {
            command: Some(named.to_string_lossy().into_owned()),
            ..AdvisoryConfig::default()
        };
        assert_eq!(
            resolve_advisor(&config, config_home.path()),
            Resolution::Found {
                path: named,
                origin: Origin::Configured
            }
        );
    }

    /// An advisor runs with this account's privileges. One that another account
    /// can rewrite would be degu executing their decision, so it is refused —
    /// and said out loud, because a reader who put it there meant it to run.
    #[test]
    fn a_group_writable_advisor_is_refused_rather_than_skipped() {
        let config_home = tempfile::tempdir().expect("a config home");
        let degu = config_home.path().join("degu");
        std::fs::create_dir_all(&degu).expect("the degu config directory");
        executable(&degu, CONVENTION_NAME, 0o770);
        let Resolution::Refused { reason, .. } =
            resolve_advisor(&AdvisoryConfig::default(), config_home.path())
        else {
            panic!("a group-writable advisor was admitted");
        };
        assert!(reason.contains("writable"), "{reason}");
    }

    #[test]
    fn a_non_executable_advisor_is_refused_rather_than_skipped() {
        let config_home = tempfile::tempdir().expect("a config home");
        let degu = config_home.path().join("degu");
        std::fs::create_dir_all(&degu).expect("the degu config directory");
        executable(&degu, CONVENTION_NAME, 0o600);
        let Resolution::Refused { reason, .. } =
            resolve_advisor(&AdvisoryConfig::default(), config_home.path())
        else {
            panic!("a non-executable advisor was admitted");
        };
        assert!(reason.contains("executable"), "{reason}");
    }

    /// A named path that is not there is a mistake; an absent convention is the
    /// ordinary case. They must not read alike.
    #[test]
    fn a_named_advisor_that_is_missing_is_a_mistake_not_an_absence() {
        let config_home = tempfile::tempdir().expect("a config home");
        let config = AdvisoryConfig {
            command: Some("/nonexistent/degu-advisor".to_owned()),
            ..AdvisoryConfig::default()
        };
        let Resolution::Refused { reason, .. } = resolve_advisor(&config, config_home.path())
        else {
            panic!("a missing named advisor was not reported");
        };
        assert!(reason.contains("nothing exists"), "{reason}");
    }

    /// The pane can be turned off entirely, and then degu asks nobody anything.
    /// Off means the reader sees nothing about advisories at all, which the
    /// pane needs to be able to tell apart from an advisor that ran and had
    /// nothing to say.
    #[test]
    fn a_disabled_advisory_consults_nothing_and_says_nothing() {
        let findings = [unknown_recovery("/home/account/.cache/mystery")];
        let config = AdvisoryConfig {
            enabled: false,
            command: Some("/bin/advisor".to_owned()),
            ..AdvisoryConfig::default()
        };
        let advisories = consult(&config, &findings, &home(), Path::new("/nonexistent"));
        assert!(advisories.disabled());
        assert_eq!(advisories.unavailable(), None);
        assert_eq!(advisories.source(), None);
        assert!(
            advisories
                .for_path(Path::new("/home/account/.cache/mystery"))
                .is_none()
        );
    }

    /// Running somebody's program costs them something, and a scan where degu
    /// classified everything has nothing to ask about. Observed rather than
    /// argued: the advisor records that it ran, and it must not have.
    #[test]
    fn nothing_to_ask_about_starts_no_program() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("a directory");
        let witness = directory.path().join("ran");
        let advisor = directory.path().join("advisor");
        std::fs::write(
            &advisor,
            format!("#!/bin/sh\ntouch {}\n", witness.display()),
        )
        .expect("a script");
        std::fs::set_permissions(&advisor, std::fs::Permissions::from_mode(0o700)).expect("a mode");
        let config = AdvisoryConfig {
            command: Some(advisor.to_string_lossy().into_owned()),
            ..AdvisoryConfig::default()
        };

        let classified = [eligible("/home/account/.cache/pip")];
        let advisories = consult(&config, &classified, &home(), directory.path());
        assert!(!witness.exists(), "the advisor ran with nothing to ask");
        assert_eq!(advisories.unavailable(), None);

        // The same advisor does run once there is something degu cannot name,
        // so the absence above is about the question, not about the wiring.
        let unnamed = [unknown_recovery("/home/account/.cache/mystery")];
        let _ = consult(&config, &unnamed, &home(), directory.path());
        assert!(witness.exists(), "the advisor was never reachable at all");
    }

    #[test]
    fn a_request_is_bounded_in_subjects() {
        let paths: Vec<String> = (0..MAX_SUBJECTS + 10)
            .map(|index| format!("/home/account/.cache/m{index}"))
            .collect();
        let findings: Vec<Finding> = paths.iter().map(|path| unknown_recovery(path)).collect();
        assert_eq!(subjects(&findings, &home()).len(), MAX_SUBJECTS);
    }
}
