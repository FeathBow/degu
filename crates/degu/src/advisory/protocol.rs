use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use degu_core::finding::Finding;

use super::Advice;

/// Findings sent in one request. An advisor is consulted about what degu could
/// not name, not about everything it found, so this bounds a request to the
/// largest handful worth asking about.
pub(super) const MAX_SUBJECTS: usize = 32;

/// Room for a paragraph, not an essay. A pane has to stay readable, and an
/// advisor that writes past this is not answering the question.
pub(super) const MAX_SUMMARY_CHARS: usize = 600;
pub(super) const MAX_CHECK_CHARS: usize = 160;

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
pub(super) struct Subject {
    /// The finding this subject was built from, kept so an answer can be put
    /// back where it belongs. Never serialized: `path` is what an advisor is
    /// shown, and that one is anonymized.
    #[serde(skip)]
    pub(super) target: PathBuf,
    pub(super) id: String,
    pub(super) path: String,
    /// The ancestors were not sent, because they could not be anonymized.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(super) ancestors_withheld: bool,
    pub(super) name: String,
    pub(super) ecosystem: String,
    pub(super) kind: &'static str,
    pub(super) bytes_allocated: u64,
    pub(super) inodes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) age_days: Option<u64>,
    pub(super) measurement_incomplete: bool,
    pub(super) reason: String,
}

#[derive(serde::Serialize)]
pub(super) struct Request<'a> {
    pub(super) degu_advisory_request: u32,
    pub(super) subjects: &'a [Subject],
}

#[derive(serde::Deserialize)]
pub(super) struct Response {
    #[serde(default)]
    advice: Vec<ResponseAdvice>,
}

#[derive(serde::Deserialize)]
struct ResponseAdvice {
    pub(super) id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    check: Option<String>,
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

pub(super) fn subjects(findings: &[Finding], home: &Path) -> Vec<Subject> {
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
/// Map answers back onto the locations degu asked about, never onto paths an
/// advisor names.
///
/// An advisor answers by the id it was given, and the subject carries the
/// finding it was built from, so an answer returns to that location and nowhere
/// else. A path in a response is ignored entirely. Keying this off the name an
/// advisor was shown would not work: that name is anonymized for anything
/// outside the account home, which is the ordinary case on a shared filesystem.
pub(super) fn resolve(response: &Response, subjects: &[Subject]) -> BTreeMap<PathBuf, Advice> {
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
pub(super) fn bounded(text: &str, limit: usize) -> String {
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
