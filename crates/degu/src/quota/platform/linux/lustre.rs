//! Lustre quota provider backed by the `lfs` client tool: the user, and for a
//! survey the path's project and group as well.
//!
//! There is no stable kernel ABI for Lustre quota queries, so this provider
//! executes `/usr/bin/lfs quota` and parses its stdout under a strict
//! whole-output grammar. Any deviation from that grammar fails closed with an
//! honest error instead of risking a wrong number.
//!
//! Threat boundary: the exec hardening in `tool` (absolute binary path, cleared
//! environment, pinned C locale, neutral working directory, closed stdin,
//! bounded concurrent output capture, bounded timeout, escaped error text)
//! defends against confusion: PATH or environment injection, locale drift,
//! hostile bytes in the output stream, and Lustre servers that hang. It does
//! not defend against a hostile root: whoever controls /usr/bin/lfs already
//! controls this process's view of the filesystem. One residual is accepted:
//! the in-process statfs cross-check and path canonicalization below run
//! before the time-bounded child and can still block on a mount whose
//! servers are unresponsive. `degu quota` bounds that with a deadline of its own;
//! a clean's observation hangs honestly rather than printing a number it could
//! not verify.

use super::tool::{
    self, Execution, ToolRun, kib_to_bytes, numeric_plain, numeric_usage, reason_snippet,
    unavailable,
};
use super::{MountInfo, ProbeError, QuotaHost};
use crate::quota::model::{
    ActiveQuota, QuotaDimension, QuotaGrace, QuotaGraceState, QuotaLimits, QuotaSnapshot,
    SubjectQuota,
};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

const PROVIDER: &str = "lustre_lfs";
const DATA_SOURCE: &str = "lfs_quota";
pub(super) const FILESYSTEM: &str = "lustre";
/// The only binary this provider will ever execute. No PATH resolution and
/// no fallback locations: a missing tool is an honest Unavailable error.
pub(super) const LFS_BINARY: &str = "/usr/bin/lfs";
const LUSTRE_SUPER_MAGIC: u64 = 0x0BD0_0BD0;
const LFS_TIMEOUT: Duration = Duration::from_secs(10);
const QUOTAS_NOT_ENABLED_MARKER: &str = "quotas are not enabled";
/// Column-header token sequences, one per lfs generation. The legacy header
/// repeats `quota limit grace` for both dimensions; current lustre-release
/// master (lfs.c print_quota_title at commit 90dfed83) renames the limit and
/// grace columns with b/i prefixes. Column order and the data-row grammar are
/// identical across generations, so only this header check branches.
const LEGACY_COLUMN_HEADER: [&str; 9] = [
    "Filesystem",
    "kbytes",
    "quota",
    "limit",
    "grace",
    "files",
    "quota",
    "limit",
    "grace",
];
const CURRENT_COLUMN_HEADER: [&str; 9] = [
    "Filesystem",
    "kbytes",
    "bquota",
    "blimit",
    "bgrace",
    "files",
    "iquota",
    "ilimit",
    "igrace",
];
const VALUE_COLUMN_COUNT: usize = 8;
/// Countdown units as printed by lfs, in the mandatory descending order.
const COUNTDOWN_UNITS: [(u8, u64); 5] = [
    (b'w', 7 * 24 * 60 * 60),
    (b'd', 24 * 60 * 60),
    (b'h', 60 * 60),
    (b'm', 60),
    (b's', 1),
];

type IncompleteReason = String;

/// The parsed result of one strictly validated `lfs quota` invocation.
#[derive(Debug)]
struct Parsed {
    space: QuotaDimension,
    inodes: QuotaDimension,
}

/// Who a quota row belongs to, spelled as `lfs` spells it.
#[derive(Clone, Copy, Debug)]
enum SubjectKind {
    User,
    Group,
    Project,
}

impl SubjectKind {
    fn flag(self) -> &'static str {
        match self {
            Self::User => "-u",
            Self::Group => "-g",
            Self::Project => "-p",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Project => "project",
        }
    }

    /// `lfs` prints `usr`, `grp` and `prj`; some builds spell the word out.
    fn header_words(self) -> [&'static str; 2] {
        match self {
            Self::User => ["usr", "user"],
            Self::Group => ["grp", "group"],
            Self::Project => ["prj", "project"],
        }
    }

    fn id_label(self) -> &'static str {
        match self {
            Self::User => "uid",
            Self::Group => "gid",
            Self::Project => "pid",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Subject {
    kind: SubjectKind,
    id: u32,
}

impl Subject {
    fn user(id: u32) -> Self {
        Self {
            kind: SubjectKind::User,
            id,
        }
    }
}

pub(super) fn probe(
    host: &QuotaHost,
    mount: MountInfo,
    path: &Path,
    subject_id: u32,
) -> Result<QuotaSnapshot, ProbeError> {
    let parsed = read_subject(host, &mount, Subject::user(subject_id))?;
    let scope = mount.scope(path);
    Ok(QuotaSnapshot::active(
        scope,
        subject_id,
        ActiveQuota {
            provider: PROVIDER,
            data_source: DATA_SOURCE,
            space: parsed.space,
            inodes: parsed.inodes,
        },
    ))
}

/// The user, and the project and group this path answers to. On a Lustre site
/// the limit that stops a write is usually the project's: a user can have none
/// and still be nearly out of the project's inodes. Only the user's failure
/// fails the survey. Any other is reported beside what could be read.
pub(super) fn survey(
    host: &QuotaHost,
    mount: MountInfo,
    path: &Path,
    subject_id: u32,
    group: Result<u32, String>,
) -> Result<QuotaSnapshot, ProbeError> {
    let snapshot = probe(host, mount.clone(), path, subject_id)?;
    let mut others = Vec::new();
    match project_of(&host.lfs, &mount, path) {
        Ok(None) => {}
        Ok(Some(id)) => others.push(subject_quota(host, &mount, SubjectKind::Project, id)),
        Err(error) => others.push(SubjectQuota::unavailable(
            SubjectKind::Project.name(),
            None,
            error.reason_text(),
        )),
    }
    others.push(match group {
        Ok(id) => subject_quota(host, &mount, SubjectKind::Group, id),
        Err(reason) => SubjectQuota::unavailable(SubjectKind::Group.name(), None, reason),
    });
    Ok(snapshot.with_subjects(others))
}

fn subject_quota(host: &QuotaHost, mount: &MountInfo, kind: SubjectKind, id: u32) -> SubjectQuota {
    match read_subject(host, mount, Subject { kind, id }) {
        Ok(parsed) => SubjectQuota::active(kind.name(), id, parsed.space, parsed.inodes),
        Err(error) => SubjectQuota::unavailable(kind.name(), Some(id), error.reason_text()),
    }
}

fn read_subject(
    host: &QuotaHost,
    mount: &MountInfo,
    subject: Subject,
) -> Result<Parsed, ProbeError> {
    tool::require_rooted_mount_point(mount)?;
    if host.check_magic {
        verify_statfs_is_lustre(mount)?;
    }
    let execution = capture(&host.lfs, mount, subject, LFS_TIMEOUT)?;
    let stdout = successful_stdout(mount, execution)?;
    // Sampled right after lfs exits, so it sits closest to the instant the
    // server produced the countdown that expires_at_unix is derived from.
    let observed_at_unix =
        super::unix_time_now().map_err(|reason| super::incomplete(mount, reason))?;
    parse(&stdout, &mount.mount_point, subject, observed_at_unix)
        .map_err(|reason| super::incomplete(mount, reason))
}

/// The project this path is charged to, or `None` for project 0, which means it
/// has none. `path` is canonical, so absolute, and cannot read as an option.
fn project_of(binary: &Path, mount: &MountInfo, path: &Path) -> Result<Option<u32>, ProbeError> {
    let execution = tool::capture(
        ToolRun {
            binary,
            tool: "lfs",
            arguments: &[OsStr::new("project"), OsStr::new("-d"), path.as_os_str()],
            timeout: LFS_TIMEOUT,
        },
        mount,
    )?;
    let stdout = successful_stdout(mount, execution)?;
    parse_project(&stdout, path).map_err(|reason| super::incomplete(mount, reason))
}

/// `lfs project -d` prints one line: the id, `P` or `-` for the inherit flag, and
/// the path it was given. The path is compared rather than parsed, so one with
/// spaces in it is fine, and a line about another path fails closed.
fn parse_project(stdout: &str, path: &Path) -> Result<Option<u32>, IncompleteReason> {
    let path_text = path
        .to_str()
        .ok_or_else(|| "quota target is not valid UTF-8".to_owned())?;
    let mut lines = stdout.lines();
    let line = lines
        .next()
        .ok_or_else(|| "lfs project printed no output".to_owned())?;
    if lines.next().is_some() {
        return Err("lfs project printed more than one line".to_owned());
    }
    let line = line.trim_start();
    let (id, rest) = line
        .split_once(' ')
        .ok_or_else(|| "lfs project line has no flag column".to_owned())?;
    let rest = rest.trim_start();
    let named = rest
        .strip_prefix("P ")
        .or_else(|| rest.strip_prefix("- "))
        .ok_or_else(|| "lfs project line has no recognized flag".to_owned())?;
    if named != path_text {
        return Err("lfs project line names another path".to_owned());
    }
    let id: u32 = id
        .parse()
        .map_err(|_| "lfs project id is not numeric".to_owned())?;
    Ok((id != 0).then_some(id))
}

/// Cross-check: mountinfo said "lustre"; require the kernel's statfs magic to
/// agree before executing lfs against this mount point.
fn verify_statfs_is_lustre(mount: &MountInfo) -> Result<(), ProbeError> {
    tool::verify_statfs(mount, LUSTRE_SUPER_MAGIC)
}

fn capture(
    binary: &Path,
    mount: &MountInfo,
    subject: Subject,
    timeout: Duration,
) -> Result<Execution, ProbeError> {
    let id = subject.id.to_string();
    // argv fixed to ["quota", <flag>, <numeric id>, <mount point>].
    tool::capture(
        ToolRun {
            binary,
            tool: "lfs",
            arguments: &[
                OsStr::new("quota"),
                OsStr::new(subject.kind.flag()),
                OsStr::new(&id),
                mount.mount_point.as_os_str(),
            ],
            timeout,
        },
        mount,
    )
}

/// Exit status is a hard precondition: stdout is parsed only when lfs exited
/// zero. Upstream lfs exits non-zero whenever it degrades its own output --
/// bracketed `[N]` placeholder values, EREMOTEIO-polluted rows, and the
/// "Some errors happened" trailer all ride on non-zero exits -- so none of
/// them can reach the parser. The grammar still rejects them independently.
fn successful_stdout(mount: &MountInfo, execution: Execution) -> Result<String, ProbeError> {
    if !execution.status.success() {
        let stderr = String::from_utf8_lossy(&execution.stderr.bytes);
        if stderr.contains(QUOTAS_NOT_ENABLED_MARKER) {
            return Err(ProbeError::NotConfigured {
                filesystem: mount.filesystem.clone(),
                mount_point: mount.mount_point.display().to_string(),
            });
        }
        return Err(unavailable(
            mount,
            format!(
                "lfs quota failed ({}): {}",
                execution.status,
                reason_snippet(&stderr)
            ),
        ));
    }
    if execution.stdout.truncated {
        return Err(super::incomplete(
            mount,
            "lfs stdout exceeded the 64 KiB capture bound",
        ));
    }
    if execution.stderr.truncated {
        return Err(super::incomplete(
            mount,
            "lfs stderr exceeded the 64 KiB capture bound",
        ));
    }
    // A zero exit does not prove a clean run: an lfs build can degrade (partial
    // OST/MDT answers, config warnings) while still exiting 0, so any stderr
    // output disqualifies the report instead of silently vanishing.
    if !execution.stderr.bytes.is_empty() {
        let stderr = String::from_utf8_lossy(&execution.stderr.bytes);
        return Err(super::incomplete(
            mount,
            format!(
                "lfs succeeded but wrote to stderr: {}",
                reason_snippet(&stderr)
            ),
        ));
    }
    String::from_utf8(execution.stdout.bytes)
        .map_err(|_| super::incomplete(mount, "lfs stdout is not valid UTF-8"))
}

/// Strict whole-output grammar for `lfs quota -u <euid> <mount point>`.
///
/// Pure function: no process state, unit-testable with fixture text. Every
/// deviation returns a line-specific Incomplete reason; nothing is guessed.
fn parse(
    stdout: &str,
    mount_point: &Path,
    subject: Subject,
    observed_at_unix: u64,
) -> Result<Parsed, IncompleteReason> {
    let mount_text = mount_point
        .to_str()
        .ok_or_else(|| "mount point is not valid UTF-8".to_owned())?;
    let mut lines = stdout.lines();
    parse_header(
        lines
            .next()
            .ok_or_else(|| "lfs printed no output".to_owned())?,
        subject,
    )?;
    parse_column_header(
        lines
            .next()
            .ok_or_else(|| "output ended before the column header".to_owned())?,
    )?;
    let columns = parse_data_row(&mut lines, mount_text)?;
    let parsed = parse_columns(columns, observed_at_unix)?;
    parse_trailers(lines, subject)?;
    Ok(parsed)
}

/// Line 1: `Disk quotas for usr <name> (uid N):`, or `grp` and `gid`, or `prj` and
/// `pid`. Vanilla builds print the short word and some builds print `user`; the
/// name field is unvalidated, but the trailing anchor must match the probed
/// subject exactly.
fn parse_header(line: &str, subject: Subject) -> Result<(), IncompleteReason> {
    let label = subject.kind.id_label();
    let [short, long] = subject.kind.header_words();
    let rest = line
        .strip_prefix(&format!("Disk quotas for {short} "))
        .or_else(|| line.strip_prefix(&format!("Disk quotas for {long} ")))
        .ok_or_else(|| format!("first line is not a {} quota header", subject.kind.name()))?;
    // Anchor on the last " (uid " so a hostile name cannot fake it.
    let (_, id_text) = rest
        .rsplit_once(&format!(" ({label} "))
        .ok_or_else(|| format!("quota header lacks a ({label} N): anchor"))?;
    let digits = id_text
        .strip_suffix("):")
        .ok_or_else(|| format!("quota header lacks a ({label} N): anchor"))?;
    let id: u32 = digits
        .parse()
        .map_err(|_| format!("quota header {label} is not numeric"))?;
    if id != subject.id {
        return Err(format!(
            "quota header reports {label} {id}, expected {}",
            subject.id
        ));
    }
    Ok(())
}

/// Line 2: the raw-kbytes column header, width-independent. Exactly two full
/// token sequences are accepted -- the legacy spelling and the current one --
/// so a mixed-generation header matches neither and fails closed, as does the
/// `quota_id` column of the qid-listing modes this provider never invokes. A
/// `used` token marks `-h`-style human units, which it never requests either.
fn parse_column_header(line: &str) -> Result<(), IncompleteReason> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.contains(&"used") {
        return Err("column header reports human-readable units instead of kbytes".to_owned());
    }
    if tokens != LEGACY_COLUMN_HEADER && tokens != CURRENT_COLUMN_HEADER {
        return Err("second line is not a recognized column header".to_owned());
    }
    Ok(())
}

/// Exactly one data row in one of two shapes. The path column is never
/// whitespace-split: the wrapped shape requires a line byte-equal to the
/// mount point, and the inline shape byte-prefix-strips it, so mount points
/// containing spaces parse correctly. A mount point with a leading space or
/// an embedded newline cannot match either shape and fails closed, which is
/// the acceptable outcome for such a hostile mount table.
fn parse_data_row<'output>(
    lines: &mut std::str::Lines<'output>,
    mount_text: &str,
) -> Result<[&'output str; VALUE_COLUMN_COUNT], IncompleteReason> {
    let first = lines
        .next()
        .ok_or_else(|| "output ended before the data row".to_owned())?;
    // Wrapped shape: a long path sits alone on its line and the eight value
    // columns follow on the next line.
    if first == mount_text {
        let values = lines
            .next()
            .ok_or_else(|| "wrapped data row ended before its value line".to_owned())?;
        return exactly_eight(values.split_whitespace().collect());
    }
    // Inline shape: indentation, then the path, then the value columns.
    let remainder = first
        .trim_start()
        .strip_prefix(mount_text)
        .ok_or_else(|| "data row does not begin with the probed mount point".to_owned())?;
    if !remainder.is_empty() && !remainder.starts_with(|character: char| character.is_whitespace())
    {
        return Err("data row glues the mount point to another token".to_owned());
    }
    exactly_eight(remainder.split_whitespace().collect())
}

fn exactly_eight(tokens: Vec<&str>) -> Result<[&str; VALUE_COLUMN_COUNT], IncompleteReason> {
    let count = tokens.len();
    tokens
        .try_into()
        .map_err(|_| format!("expected {VALUE_COLUMN_COUNT} value columns, found {count}"))
}

fn parse_columns(
    columns: [&str; VALUE_COLUMN_COUNT],
    observed_at_unix: u64,
) -> Result<Parsed, IncompleteReason> {
    let [
        kbytes,
        block_soft,
        block_hard,
        block_grace,
        files,
        inode_soft,
        inode_hard,
        inode_grace,
    ] = columns;
    let space = QuotaDimension::new(
        kib_to_bytes(numeric_usage(kbytes, "kbytes")?, "kbytes")?,
        QuotaLimits::new(
            kib_to_bytes(
                numeric_plain(block_soft, "block soft limit")?,
                "block soft limit",
            )?,
            kib_to_bytes(
                numeric_plain(block_hard, "block hard limit")?,
                "block hard limit",
            )?,
        ),
        parse_grace(block_grace, observed_at_unix, "block grace")?,
    );
    let inodes = QuotaDimension::new(
        numeric_usage(files, "files")?,
        QuotaLimits::new(
            numeric_plain(inode_soft, "inode soft limit")?,
            numeric_plain(inode_hard, "inode hard limit")?,
        ),
        parse_grace(inode_grace, observed_at_unix, "inode grace")?,
    );
    Ok(Parsed { space, inodes })
}

/// Grace column: `-` means no grace period is running. Vanilla Lustre 2.15
/// prints `none` for an expired grace period while the Cray fork prints
/// `expired`; both map to Expired with no deadline, because lfs reports no
/// deadline for them and degu never synthesizes one. A countdown maps to
/// Active with a deadline derived from the observation instant, accurate to
/// about the runtime of the lfs call (a few seconds).
fn parse_grace(
    token: &str,
    observed_at_unix: u64,
    column: &str,
) -> Result<Option<QuotaGrace>, IncompleteReason> {
    match token {
        "-" => Ok(None),
        "none" | "expired" => Ok(Some(QuotaGrace {
            state: QuotaGraceState::Expired,
            expires_at_unix: None,
        })),
        _ => {
            let seconds = countdown_seconds(token)
                .ok_or_else(|| format!("{column} column is not a recognized grace value"))?;
            let expires_at_unix = observed_at_unix
                .checked_add(seconds)
                .ok_or_else(|| format!("{column} deadline overflows the Unix clock"))?;
            Ok(Some(QuotaGrace {
                state: QuotaGraceState::Active,
                expires_at_unix: Some(expires_at_unix),
            }))
        }
    }
}

/// Countdown grammar: `(\d+w)?(\d+d)?(\d+h)?(\d+m)?(\d+s)?`, non-empty, units
/// strictly descending, `0s` valid. All arithmetic is checked.
fn countdown_seconds(token: &str) -> Option<u64> {
    let mut rest = token.as_bytes();
    let mut total: u64 = 0;
    for (unit, unit_seconds) in COUNTDOWN_UNITS {
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if digits == 0 || rest.get(digits) != Some(&unit) {
            continue;
        }
        let value: u64 = std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()?;
        total = total.checked_add(value.checked_mul(unit_seconds)?)?;
        rest = &rest[digits + 1..];
    }
    (!token.is_empty() && rest.is_empty()).then_some(total)
}

/// Optional trailers, in order, each independently optional. lfs prints them
/// when the subject has no explicitly configured limits. Anything else after the
/// data row -- a second usr/grp block, an error trailer -- fails closed.
fn parse_trailers(lines: std::str::Lines<'_>, subject: Subject) -> Result<(), IncompleteReason> {
    let label = subject.kind.id_label();
    let id = subject.id;
    let expected = [
        format!("{label} {id} is using default block quota setting"),
        format!("{label} {id} is using default file quota setting"),
    ];
    let mut next = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        match expected[next..]
            .iter()
            .position(|candidate| line == candidate)
        {
            Some(offset) => next += offset + 1,
            None => return Err("unexpected line after the quota data row".to_owned()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::tool::{CappedStream, require_rooted_mount_point};
    use super::{
        LFS_TIMEOUT, MountInfo, Parsed, ProbeError, QuotaGraceState, QuotaHost, Subject,
        SubjectKind, capture, countdown_seconds, parse, parse_project, project_of, subject_quota,
        successful_stdout, survey, verify_statfs_is_lustre,
    };
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::time::Duration;

    const EUID: u32 = 12345;
    const OBSERVED_AT: u64 = 1_700_000_000;
    const MOUNT: &str = "/scratch";
    const HEADER: &str = "Disk quotas for usr researcher (uid 12345):";
    const COLUMNS: &str =
        "     Filesystem  kbytes   quota   limit   grace   files   quota   limit   grace";
    /// Current lustre-release master spelling (lfs.c print_quota_title at
    /// commit 90dfed83), spaced as the fixed-width upstream printf emits it.
    const NEW_COLUMNS: &str =
        "     Filesystem  kbytes  bquota  blimit  bgrace   files  iquota  ilimit  igrace";
    const BLOCK_TRAILER: &str = "uid 12345 is using default block quota setting";
    const FILE_TRAILER: &str = "uid 12345 is using default file quota setting";

    fn fixture(lines: &[&str]) -> String {
        let mut output = lines.join("\n");
        output.push('\n');
        output
    }

    fn parse_fixture(stdout: &str) -> Result<Parsed, String> {
        parse(stdout, Path::new(MOUNT), Subject::user(EUID), OBSERVED_AT)
    }

    #[test]
    fn lustre_parser_rejects_starred_limit_columns() {
        for row in [
            "       /scratch 1024 2048* 4096 - 10 20 40 -",
            "       /scratch 1024 2048 4096* - 10 20 40 -",
            "       /scratch 1024 2048 4096 - 10 20* 40 -",
            "       /scratch 1024 2048 4096 - 10 20 40* -",
        ] {
            let stdout = fixture(&[HEADER, COLUMNS, row]);
            let error = parse_fixture(&stdout).unwrap_err();
            assert!(
                format!("{error:?}").contains("not an unsigned integer"),
                "{row}: {error:?}"
            );
        }
    }

    #[test]
    fn lustre_parser_accepts_starred_usage_columns() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 1024* 2048 4096 - 10* 20 40 -",
        ]);
        let parsed = parse_fixture(&stdout).unwrap();
        assert_eq!(parsed.space.used, 1024 * 1024);
        assert_eq!(parsed.inodes.used, 10);
    }

    #[test]
    fn lustre_parser_accepts_inline_zero_limits_with_both_trailers() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 9916279124       0       0       - 25923767       0       0       -",
            BLOCK_TRAILER,
            FILE_TRAILER,
        ]);
        let parsed = parse_fixture(&stdout).unwrap();
        assert_eq!(parsed.space.used, 9_916_279_124 * 1024);
        assert_eq!(parsed.space.soft_limit, None);
        assert_eq!(parsed.space.hard_limit, None);
        assert!(parsed.space.grace.is_none());
        assert_eq!(parsed.inodes.used, 25_923_767);
        assert_eq!(parsed.inodes.soft_limit, None);
        assert_eq!(parsed.inodes.hard_limit, None);
        assert!(parsed.inodes.grace.is_none());
    }

    #[test]
    fn lustre_parser_accepts_a_wrapped_long_path_with_one_trailer() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "/scratch/lab/researcher",
            "                9916279124       0       0       - 25923767       0       0       -",
            BLOCK_TRAILER,
        ]);
        let parsed = parse(
            &stdout,
            Path::new("/scratch/lab/researcher"),
            Subject::user(EUID),
            OBSERVED_AT,
        )
        .unwrap();
        assert_eq!(parsed.space.used, 9_916_279_124 * 1024);
        assert_eq!(parsed.inodes.used, 25_923_767);
    }

    #[test]
    fn lustre_parser_accepts_configured_limits_without_trailers() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 1024 2048 4096 - 10 20 40 -",
        ]);
        let parsed = parse_fixture(&stdout).unwrap();
        assert_eq!(parsed.space.used, 1024 * 1024);
        assert_eq!(parsed.space.soft_limit, Some(2048 * 1024));
        assert_eq!(parsed.space.hard_limit, Some(4096 * 1024));
        assert_eq!(parsed.inodes.used, 10);
        assert_eq!(parsed.inodes.soft_limit, Some(20));
        assert_eq!(parsed.inodes.hard_limit, Some(40));
    }

    #[test]
    fn lustre_parser_accepts_usr_and_user_header_spellings() {
        for header in [
            "Disk quotas for usr researcher (uid 12345):",
            "Disk quotas for user researcher (uid 12345):",
        ] {
            let stdout = fixture(&[header, COLUMNS, "       /scratch 8 0 0 - 1 0 0 -"]);
            parse_fixture(&stdout).unwrap();
        }
    }

    #[test]
    fn lustre_parser_accepts_the_current_header_with_zero_limits_and_no_trailers() {
        // Master shape: current column spellings, inline fixed-width mount,
        // no default-quota trailer lines. Values must come out identical to
        // the legacy-header equivalent fixture above.
        let stdout = fixture(&[
            HEADER,
            NEW_COLUMNS,
            "       /scratch 9916279124       0       0       - 25923767       0       0       -",
        ]);
        let parsed = parse_fixture(&stdout).unwrap();
        assert_eq!(parsed.space.used, 9_916_279_124 * 1024);
        assert_eq!(parsed.space.soft_limit, None);
        assert_eq!(parsed.space.hard_limit, None);
        assert!(parsed.space.grace.is_none());
        assert_eq!(parsed.inodes.used, 25_923_767);
        assert_eq!(parsed.inodes.soft_limit, None);
        assert_eq!(parsed.inodes.hard_limit, None);
        assert!(parsed.inodes.grace.is_none());
    }

    #[test]
    fn lustre_parser_derives_an_active_deadline_under_the_current_header() {
        let stdout = fixture(&[
            HEADER,
            NEW_COLUMNS,
            "       /scratch 3000000* 2000000 4000000 6d23h56m44s 100 0 0 -",
        ]);
        let parsed = parse_fixture(&stdout).unwrap();
        assert_eq!(parsed.space.used, 3_000_000 * 1024);
        assert_eq!(parsed.space.soft_limit, Some(2_000_000 * 1024));
        assert_eq!(parsed.space.hard_limit, Some(4_000_000 * 1024));
        let grace = parsed.space.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Active);
        let expected = 6 * 86_400 + 23 * 3_600 + 56 * 60 + 44;
        assert_eq!(grace.expires_at_unix, Some(OBSERVED_AT + expected));
    }

    #[test]
    fn lustre_parser_maps_expired_and_none_to_expired_under_the_current_header() {
        for token in ["expired", "none"] {
            let row = format!("       /scratch 3000000* 2000000 4000000 {token} 100 0 0 -");
            let stdout = fixture(&[HEADER, NEW_COLUMNS, &row]);
            let grace = parse_fixture(&stdout).unwrap().space.grace.unwrap();
            assert_eq!(grace.state, QuotaGraceState::Expired);
            assert_eq!(grace.expires_at_unix, None);
        }
    }

    #[test]
    fn lustre_parser_rejects_mixed_generation_column_headers() {
        // Per-token OR-ing would wave these through; the header must match
        // one full generation or fail closed.
        for columns in [
            "     Filesystem  kbytes   quota   limit   grace   files  iquota  ilimit  igrace",
            "     Filesystem  kbytes  bquota  blimit  bgrace   files   quota   limit   grace",
        ] {
            let stdout = fixture(&[HEADER, columns, "       /scratch 8 0 0 - 1 0 0 -"]);
            let reason = parse_fixture(&stdout).unwrap_err();
            assert!(reason.contains("column header"), "{reason}");
        }
    }

    #[test]
    fn lustre_parser_rejects_used_in_the_current_column_header() {
        let stdout = fixture(&[
            HEADER,
            "     Filesystem    used  bquota  blimit  bgrace   files  iquota  ilimit  igrace",
            "       /scratch 8K 0 0 - 1 0 0 -",
        ]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("human-readable"), "{reason}");
    }

    #[test]
    fn lustre_parser_rejects_a_quota_id_column_header() {
        let stdout = fixture(&[
            HEADER,
            "     Filesystem  quota_id  kbytes  bquota  blimit  bgrace   files  iquota  ilimit  igrace",
            "       /scratch 8 0 0 - 1 0 0 -",
        ]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("column header"), "{reason}");
    }

    #[test]
    fn lustre_parser_rejects_a_header_uid_that_is_not_the_probed_euid() {
        let stdout = fixture(&[
            "Disk quotas for usr researcher (uid 99999):",
            COLUMNS,
            "       /scratch 8 0 0 - 1 0 0 -",
        ]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("uid 99999"), "{reason}");
    }

    #[test]
    fn lustre_parser_derives_an_active_deadline_from_a_starred_countdown() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 3000000* 2000000 4000000 6d23h56m44s 100 0 0 -",
        ]);
        let parsed = parse_fixture(&stdout).unwrap();
        assert_eq!(parsed.space.used, 3_000_000 * 1024);
        let grace = parsed.space.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Active);
        let expected = 6 * 86_400 + 23 * 3_600 + 56 * 60 + 44;
        assert_eq!(grace.expires_at_unix, Some(OBSERVED_AT + expected));
    }

    #[test]
    fn lustre_parser_sums_a_full_countdown_across_all_units() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 100 0 0 - 500* 400 600 1w2d3h4m5s",
        ]);
        let parsed = parse_fixture(&stdout).unwrap();
        let grace = parsed.inodes.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Active);
        assert_eq!(grace.expires_at_unix, Some(OBSERVED_AT + 788_645));
    }

    #[test]
    fn lustre_parser_maps_none_to_expired_without_a_deadline() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 3000000* 2000000 4000000 none 100 0 0 -",
        ]);
        let grace = parse_fixture(&stdout).unwrap().space.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Expired);
        assert_eq!(grace.expires_at_unix, None);
    }

    #[test]
    fn lustre_parser_maps_expired_to_expired_without_a_deadline() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 3000000* 2000000 4000000 expired 100 0 0 -",
        ]);
        let grace = parse_fixture(&stdout).unwrap().space.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Expired);
        assert_eq!(grace.expires_at_unix, None);
    }

    #[test]
    fn lustre_parser_accepts_a_zero_second_countdown() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 3000000* 2000000 4000000 0s 100 0 0 -",
        ]);
        let grace = parse_fixture(&stdout).unwrap().space.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Active);
        assert_eq!(grace.expires_at_unix, Some(OBSERVED_AT));
    }

    #[test]
    fn lustre_parser_rejects_bracketed_placeholder_values() {
        let stdout = fixture(&[HEADER, COLUMNS, "       /scratch 100 [123] 0 - 1 0 0 -"]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("block soft limit"), "{reason}");
    }

    #[test]
    fn lustre_parser_rejects_the_some_errors_happened_trailer() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 8 0 0 - 1 0 0 -",
            "Some errors happened when getting quota info. Some devices may be not working or deactivated. The data in \"[]\" is inaccurate.",
        ]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("unexpected line"), "{reason}");
    }

    #[test]
    fn lustre_parser_rejects_a_data_row_for_another_path() {
        let stdout = fixture(&[HEADER, COLUMNS, "       /other 8 0 0 - 1 0 0 -"]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("mount point"), "{reason}");
    }

    #[test]
    fn lustre_parser_rejects_a_prefix_collision_mount_point() {
        // `/scratch2` and `/scratch200` both start with the queried mount
        // point `/scratch`; without the whitespace-boundary requirement
        // after the stripped prefix, the second variant would corrupt the
        // first numeric column instead of failing.
        let glued = fixture(&[HEADER, COLUMNS, "       /scratch2 8 0 0 - 1 0 0 -"]);
        let corrupting = fixture(&[HEADER, COLUMNS, "       /scratch200 8 0 0 - 1 0 0 -"]);
        assert!(parse_fixture(&glued).unwrap_err().contains("glues"));
        assert!(parse_fixture(&corrupting).unwrap_err().contains("glues"));
    }

    #[test]
    fn lustre_parser_rejects_rows_with_seven_or_nine_columns() {
        let seven = fixture(&[HEADER, COLUMNS, "       /scratch 8 0 0 - 1 0 0"]);
        let nine = fixture(&[HEADER, COLUMNS, "       /scratch 8 0 0 - 1 0 0 - extra"]);
        assert!(parse_fixture(&seven).unwrap_err().contains("found 7"));
        assert!(parse_fixture(&nine).unwrap_err().contains("found 9"));
    }

    #[test]
    fn lustre_parser_rejects_empty_output() {
        let reason = parse_fixture("").unwrap_err();
        assert!(reason.contains("no output"), "{reason}");
    }

    #[test]
    fn lustre_parser_rejects_kbytes_that_overflow_the_byte_conversion() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 18446744073709551615 0 0 - 1 0 0 -",
        ]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("overflows"), "{reason}");
    }

    #[test]
    fn lustre_parser_prefix_strips_a_mount_point_containing_a_space() {
        let stdout = fixture(&[HEADER, COLUMNS, " /mnt/my scratch 8 0 0 - 1 0 0 -"]);
        let parsed = parse(
            &stdout,
            Path::new("/mnt/my scratch"),
            Subject::user(EUID),
            OBSERVED_AT,
        )
        .unwrap();
        assert_eq!(parsed.space.used, 8 * 1024);
        assert_eq!(parsed.inodes.used, 1);
    }

    #[test]
    fn lustre_parser_rejects_a_dual_usr_and_grp_block() {
        let stdout = fixture(&[
            HEADER,
            COLUMNS,
            "       /scratch 8 0 0 - 1 0 0 -",
            "Disk quotas for grp lab (gid 12345):",
            COLUMNS,
            "       /scratch 8 0 0 - 1 0 0 -",
        ]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("unexpected line"), "{reason}");
    }

    #[test]
    fn lustre_parser_rejects_a_human_units_column_header() {
        let stdout = fixture(&[
            HEADER,
            "     Filesystem    used   quota   limit   grace   files   quota   limit   grace",
            "       /scratch 8K 0 0 - 1 0 0 -",
        ]);
        let reason = parse_fixture(&stdout).unwrap_err();
        assert!(reason.contains("human-readable"), "{reason}");
    }

    #[test]
    fn lustre_countdown_rejects_ascending_or_repeated_units() {
        assert_eq!(countdown_seconds("6d23h56m44s"), Some(604_604));
        assert_eq!(countdown_seconds("5s1w"), None);
        assert_eq!(countdown_seconds("1w1w"), None);
        assert_eq!(countdown_seconds("12"), None);
        assert_eq!(countdown_seconds("s"), None);
        assert_eq!(countdown_seconds(""), None);
    }

    fn test_mount() -> MountInfo {
        MountInfo {
            mount_point: PathBuf::from(MOUNT),
            filesystem: "lustre".to_owned(),
            source: PathBuf::from("10.0.0.1@tcp:/scratch"),
            mount_id: 40,
            device_major: 0,
            device_minor: 42,
        }
    }

    fn stub(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        // Held across the write: a fork in another thread would inherit this
        // descriptor and the exec below would then see a writer.
        let _exclusive = crate::fork_gate::exec_fresh_file();
        let path = dir.join("lfs-stub.sh");
        std::fs::write(&path, body).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn success_status() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[test]
    fn lustre_exec_missing_binary_is_unavailable_and_names_the_path() {
        let error = capture(
            Path::new("/nonexistent/degu-test-lfs"),
            &test_mount(),
            Subject::user(EUID),
            LFS_TIMEOUT,
        )
        .unwrap_err();
        let ProbeError::Unavailable { reason, .. } = error else {
            panic!("missing binary must be unavailable: {error:?}");
        };
        assert!(reason.contains("/nonexistent/degu-test-lfs"), "{reason}");
    }

    #[test]
    fn lustre_exec_not_enabled_stderr_maps_to_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(
            dir.path(),
            "#!/bin/sh\necho 'lfs quota: quotas are not enabled.' >&2\nexit 1\n",
        );
        let mount = test_mount();
        let execution = capture(&script, &mount, Subject::user(EUID), LFS_TIMEOUT).unwrap();
        let error = successful_stdout(&mount, execution).unwrap_err();
        assert!(
            matches!(error, ProbeError::NotConfigured { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn lustre_exec_other_nonzero_exits_map_to_unavailable_with_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(
            dir.path(),
            "#!/bin/sh\necho 'lfs quota: cannot resolve mount' >&2\nexit 4\n",
        );
        let mount = test_mount();
        let execution = capture(&script, &mount, Subject::user(EUID), LFS_TIMEOUT).unwrap();
        let error = successful_stdout(&mount, execution).unwrap_err();
        let ProbeError::Unavailable { reason, .. } = error else {
            panic!("non-zero exit must be unavailable: {error:?}");
        };
        assert!(reason.contains("cannot resolve mount"), "{reason}");
    }

    #[test]
    fn lustre_exec_kills_and_reports_a_child_that_exceeds_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(dir.path(), "#!/bin/sh\nexec sleep 30\n");
        let error = capture(
            &script,
            &test_mount(),
            Subject::user(EUID),
            Duration::from_millis(200),
        )
        .unwrap_err();
        let ProbeError::Unavailable { reason, .. } = error else {
            panic!("timeout must be unavailable: {error:?}");
        };
        assert!(reason.contains("timed out"), "{reason}");
    }

    #[test]
    fn lustre_exec_returns_bounded_stdout_from_a_successful_child() {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(dir.path(), "#!/bin/sh\necho 'hello from the stub'\n");
        let mount = test_mount();
        let execution = capture(&script, &mount, Subject::user(EUID), LFS_TIMEOUT).unwrap();
        let stdout = successful_stdout(&mount, execution).unwrap();
        assert_eq!(stdout, "hello from the stub\n");
    }

    #[test]
    fn lustre_exec_truncated_stdout_fails_closed_even_on_success() {
        let mount = test_mount();
        let execution = super::Execution {
            status: success_status(),
            stdout: CappedStream {
                bytes: Vec::new(),
                truncated: true,
            },
            stderr: CappedStream {
                bytes: Vec::new(),
                truncated: false,
            },
        };
        let error = successful_stdout(&mount, execution).unwrap_err();
        assert!(matches!(error, ProbeError::Incomplete { .. }), "{error:?}");
    }

    #[test]
    fn lustre_exec_success_with_stderr_fails_closed() {
        let mount = test_mount();
        let execution = super::Execution {
            status: success_status(),
            stdout: CappedStream {
                bytes: b"valid output".to_vec(),
                truncated: false,
            },
            stderr: CappedStream {
                bytes: b"warning: ost0001 not responding".to_vec(),
                truncated: false,
            },
        };
        let error = successful_stdout(&mount, execution).unwrap_err();
        assert!(matches!(error, ProbeError::Incomplete { .. }), "{error:?}");
    }

    #[test]
    fn lustre_statfs_cross_check_rejects_non_lustre_mounts() {
        let dir = tempfile::tempdir().unwrap();
        let mount = MountInfo {
            mount_point: dir.path().to_owned(),
            filesystem: "lustre".to_owned(),
            source: PathBuf::from("10.0.0.1@tcp:/scratch"),
            mount_id: 40,
            device_major: 0,
            device_minor: 42,
        };
        let error = verify_statfs_is_lustre(&mount).unwrap_err();
        assert!(matches!(error, ProbeError::Incomplete { .. }), "{error:?}");
    }

    fn project() -> Subject {
        Subject {
            kind: SubjectKind::Project,
            id: 654_321,
        }
    }

    fn group() -> Subject {
        Subject {
            kind: SubjectKind::Group,
            id: 2000,
        }
    }

    // Real output from a Lustre 2.15 client (the Cray build), account names removed.
    const REAL_PROJECT: &str = "Disk quotas for prj 654321 (pid 654321):\n     Filesystem  kbytes   quota   limit   grace   files   quota   limit   grace\n  /lus/fs 2307527940       0 5368709120       -  828409       0 1024000       -\n";

    #[test]
    fn project_row_reports_limits() {
        let parsed = parse(REAL_PROJECT, Path::new("/lus/fs"), project(), OBSERVED_AT).unwrap();
        assert_eq!(parsed.space.hard_limit, Some(5_368_709_120 * 1024));
        assert_eq!(parsed.inodes.used, 828_409);
        assert_eq!(parsed.inodes.hard_limit, Some(1_024_000));
    }

    // The anchor is what proves the row answers the question that was asked.
    #[test]
    fn subject_anchors_the_header() {
        let wrong_id = REAL_PROJECT.replace("654321", "999");
        let reason = parse(&wrong_id, Path::new("/lus/fs"), project(), OBSERVED_AT)
            .map(|_| ())
            .unwrap_err();
        assert!(reason.contains("pid 999"), "{reason}");
        let reason = parse(REAL_PROJECT, Path::new("/lus/fs"), group(), OBSERVED_AT)
            .map(|_| ())
            .unwrap_err();
        assert!(reason.contains("group quota header"), "{reason}");
    }

    #[test]
    fn group_trailers_are_accepted() {
        let stdout = fixture(&[
            "Disk quotas for grp 2000 (gid 2000):",
            COLUMNS,
            "  /lus/fs 3134131868       0       0       - 5837102       0       0       -",
            "gid 2000 is using default block quota setting",
            "gid 2000 is using default file quota setting",
        ]);
        let parsed = parse(&stdout, Path::new("/lus/fs"), group(), OBSERVED_AT).unwrap();
        assert_eq!(parsed.space.hard_limit, None);
        assert_eq!(parsed.inodes.used, 5_837_102);
        // Another subject's trailer is not this one's.
        let stray = fixture(&[
            "Disk quotas for grp 2000 (gid 2000):",
            COLUMNS,
            "  /lus/fs 1 0 0 - 1 0 0 -",
            "uid 2000 is using default block quota setting",
        ]);
        let reason = parse(&stray, Path::new("/lus/fs"), group(), OBSERVED_AT)
            .map(|_| ())
            .unwrap_err();
        assert!(reason.contains("unexpected line"), "{reason}");
    }

    #[test]
    fn subject_picks_the_flag() {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(dir.path(), "#!/bin/sh\necho \"$*\"\n");
        let mount = test_mount();
        for (subject, expected) in [
            (Subject::user(EUID), "quota -u 12345 /scratch\n"),
            (group(), "quota -g 2000 /scratch\n"),
            (project(), "quota -p 654321 /scratch\n"),
        ] {
            let execution = capture(&script, &mount, subject, LFS_TIMEOUT).unwrap();
            assert_eq!(String::from_utf8(execution.stdout.bytes).unwrap(), expected);
        }
    }

    #[test]
    fn project_query_names_the_target() {
        let dir = tempfile::tempdir().unwrap();
        // Echoes the id only when asked exactly this, and otherwise prints nothing.
        let script = stub(
            dir.path(),
            "#!/bin/sh\n[ \"$*\" = 'project -d /scratch/me' ] && echo '654321 P /scratch/me'\n",
        );
        let id = project_of(&script, &test_mount(), Path::new("/scratch/me")).unwrap();
        assert_eq!(id, Some(654_321));
    }

    #[test]
    fn project_line_shapes() {
        let target = Path::new("/lus/fs/scratch/me");
        assert_eq!(
            parse_project("654321 P /lus/fs/scratch/me\n", target),
            Ok(Some(654_321))
        );
        // Project 0 is how a path says it has no project.
        assert_eq!(
            parse_project("    0 - /lus/fs/scratch/me\n", target),
            Ok(None)
        );
        assert_eq!(
            parse_project("7 P /lus/my scratch\n", Path::new("/lus/my scratch")),
            Ok(Some(7))
        );
    }

    #[test]
    fn project_line_fails_closed() {
        let target = Path::new("/lus/fs/me");
        for (stdout, expected) in [
            ("", "no output"),
            ("7 P /lus/fs/me\n8 P /lus/fs/me\n", "more than one line"),
            ("7\n", "no flag column"),
            ("7 Q /lus/fs/me\n", "no recognized flag"),
            ("7 P /lus/fs/other\n", "another path"),
            ("x P /lus/fs/me\n", "not numeric"),
            ("-1 P /lus/fs/me\n", "not numeric"),
        ] {
            let reason = parse_project(stdout, target).unwrap_err();
            assert!(reason.contains(expected), "{stdout:?}: {reason}");
        }
    }

    #[test]
    fn project_refusal_is_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(
            dir.path(),
            "#!/bin/sh\necho \"lfs: failed to get xattr: Inappropriate ioctl for device\" >&2\nexit 25\n",
        );
        let error = project_of(&script, &test_mount(), Path::new("/scratch/me")).unwrap_err();
        assert!(matches!(error, ProbeError::Unavailable { .. }), "{error:?}");
        assert!(
            error.reason_text().contains("Inappropriate ioctl"),
            "{error:?}"
        );
    }

    // A subject that cannot be read must say why instead of failing the report.
    #[test]
    fn subject_failure_becomes_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let quota = subject_quota(
            &QuotaHost::standing_in(dir.path()),
            &test_mount(),
            SubjectKind::Group,
            2000,
        );
        assert_eq!(quota.kind, "group");
        assert_eq!(quota.id, Some(2000));
        assert_eq!(quota.state, "unavailable");
        assert!(
            quota
                .reason
                .as_deref()
                .is_some_and(|text| text.contains("lfs")),
            "{quota:?}"
        );
        assert!(quota.space.is_none());
    }

    /// A stand-in `lfs` answering the way a real client does, with the group
    /// query's behaviour left to the caller.
    fn stand_in(group_answer: &str) -> (tempfile::TempDir, QuotaHost) {
        let dir = tempfile::tempdir().unwrap();
        stub(
            dir.path(),
            &format!(
                "#!/bin/sh\nCOLUMNS='{COLUMNS}'\ncase \"$1 $2\" in\n'project -d') echo \"654321 P $3\" ;;\n'quota -u') echo \"Disk quotas for usr me (uid $3):\"; echo \"$COLUMNS\"; echo \"  $4 8 0 0 - 8 0 0 -\" ;;\n'quota -p') echo \"Disk quotas for prj $3 (pid $3):\"; echo \"$COLUMNS\"; echo \"  $4 2048 0 5120 - 81 0 100 -\" ;;\n'quota -g') {group_answer} ;;\nesac\n"
            ),
        );
        std::fs::rename(dir.path().join("lfs-stub.sh"), dir.path().join("lfs")).unwrap();
        let host = QuotaHost::standing_in(dir.path());
        (dir, host)
    }

    #[test]
    fn survey_reads_every_subject() {
        let (_dir, host) = stand_in(
            "echo \"Disk quotas for grp lab (gid $3):\"; echo \"$COLUMNS\"; echo \"  $4 9 0 0 - 9 0 0 -\"",
        );
        let report = survey(
            &host,
            test_mount(),
            Path::new("/scratch/me"),
            EUID,
            Ok(2000),
        )
        .unwrap();
        let others = &report.other_subjects;
        assert_eq!(others.len(), 2, "{others:?}");
        assert_eq!((others[0].kind, others[0].id), ("project", Some(654_321)));
        assert_eq!((others[1].kind, others[1].id), ("group", Some(2000)));
        let leading = report.leading_limit.as_ref().unwrap();
        assert_eq!(leading.subject_kind, "project");
        assert_eq!(leading.dimension, "inodes");
        assert!(report.limits_complete);
    }

    #[test]
    fn survey_keeps_a_partial_answer() {
        let (_dir, host) = stand_in("echo 'lfs quota: group refused' >&2; exit 1");
        let report = survey(
            &host,
            test_mount(),
            Path::new("/scratch/me"),
            EUID,
            Ok(2000),
        )
        .unwrap();
        assert_eq!(report.other_subjects[1].state, "unavailable");
        assert!(!report.limits_complete);
        // What could be read is still there.
        assert_eq!(report.other_subjects[0].state, "active");
        assert_eq!(
            report.leading_limit.as_ref().unwrap().subject_kind,
            "project"
        );
    }

    // Not knowing which group applies is reported, and no group is queried.
    #[test]
    fn survey_reports_unknown_group() {
        let (_dir, host) = stand_in("echo 'must not be asked' >&2; exit 1");
        let report = survey(
            &host,
            test_mount(),
            Path::new("/scratch/me"),
            EUID,
            Err("Permission denied".to_owned()),
        )
        .unwrap();
        let group = &report.other_subjects[1];
        assert_eq!((group.kind, group.id), ("group", None));
        assert_eq!(group.reason.as_deref(), Some("Permission denied"));
        assert!(!report.limits_complete);
    }

    #[test]
    fn lustre_relative_mount_points_fail_closed_before_exec() {
        let mount = MountInfo {
            mount_point: PathBuf::from("scratch"),
            filesystem: "lustre".to_owned(),
            source: PathBuf::from("10.0.0.1@tcp:/scratch"),
            mount_id: 40,
            device_major: 0,
            device_minor: 42,
        };
        let error = require_rooted_mount_point(&mount).unwrap_err();
        assert!(matches!(error, ProbeError::Incomplete { .. }), "{error:?}");
    }
}
