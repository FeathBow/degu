//! NFS quota provider backed by the `quota` tool, which asks the server's rquota
//! service. No syscall answers this for an unprivileged client.
//!
//! The row is the authority, not the exit status. `quota` exits non-zero when a
//! limit is exceeded, with good rows on stdout, and exits zero when the server
//! refused the question, with only a line on stderr. So a row for this mount is
//! the answer, and its absence is the failure, reported with whatever stderr
//! said. A row with zero limits is a real answer: the server has none configured.
//!
//! A row has to name both this mount point and this mount's source. The tool picks
//! the first table entry matching a directory's device and inode, so with one mount
//! on top of another at the same path it can ask the server underneath and still
//! print the path. A row that names another source fails closed.
//!
//! `-f` limits the rows to this one mount. It does not limit what the tool touches:
//! quota-tools scans every mount in the table with `realpath` and `statfs` before it
//! filters, so another mount whose server is away can make this query time out even
//! though this mount is healthy. `-v` keeps a row with no limits, which would
//! otherwise be left out and read the same as a refused query. The threat boundary
//! is the Lustre provider's: this defends against confusion, not against whoever
//! controls /usr/bin/quota.
//!
//! Only `degu quota` reaches this provider, under its own deadline. The statfs below
//! and the tool's mount scan can both block for as long as a server is away, and a
//! clean must not wait on that.

use super::tool::{
    self, Execution, ToolRun, kib_to_bytes, numeric_plain, numeric_usage, reason_snippet,
};
use super::{MountInfo, ProbeError, QuotaHost};
use crate::quota::model::{
    ActiveQuota, QuotaDimension, QuotaGrace, QuotaGraceState, QuotaLimits, QuotaSnapshot,
    SubjectQuota,
};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

pub(super) const FILESYSTEMS: [&str; 2] = ["nfs", "nfs4"];
const PROVIDER: &str = "nfs_rquota";
const DATA_SOURCE: &str = "quota_tool";
/// The only binary this provider will ever execute. No PATH resolution and
/// no fallback locations: a missing tool is an honest Unavailable error.
pub(super) const QUOTA_BINARY: &str = "/usr/bin/quota";
const NFS_SUPER_MAGIC: u64 = 0x6969;
const QUOTA_TIMEOUT: Duration = Duration::from_secs(10);
const VALUE_COLUMN_COUNT: usize = 8;
const COLUMN_HEADER: [&str; 9] = [
    "Filesystem",
    "blocks",
    "quota",
    "limit",
    "grace",
    "files",
    "quota",
    "limit",
    "grace",
];
const HEADER_PREFIX: &str = "Disk quotas for ";

#[derive(Clone, Copy, Debug)]
enum Family {
    User,
    Group,
}

impl Family {
    fn flag(self) -> &'static str {
        match self {
            Self::User => "-u",
            Self::Group => "-g",
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }

    fn id_label(self) -> &'static str {
        match self {
            Self::User => "uid",
            Self::Group => "gid",
        }
    }
}

#[derive(Debug)]
struct Parsed {
    space: QuotaDimension,
    inodes: QuotaDimension,
}

/// What a row has to name to answer for this mount, both byte for byte.
struct ExpectedRow<'a> {
    source: &'a str,
    mount_point: &'a str,
}

/// The user, and the group this path answers to. A server can answer for users
/// and refuse groups, as the one this was validated on does. That leaves the group
/// unread, not the report wrong.
pub(super) fn survey(
    host: &QuotaHost,
    mount: MountInfo,
    path: &Path,
    subject_id: u32,
    group: Result<u32, String>,
) -> Result<QuotaSnapshot, ProbeError> {
    let parsed = read_subject(host, &mount, Family::User, subject_id)?;
    let others = vec![match group {
        Ok(id) => group_quota(host, &mount, id),
        Err(reason) => SubjectQuota::unavailable(Family::Group.word(), None, reason),
    }];
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
    )
    .with_subjects(others))
}

fn group_quota(host: &QuotaHost, mount: &MountInfo, id: u32) -> SubjectQuota {
    let word = Family::Group.word();
    match read_subject(host, mount, Family::Group, id) {
        Ok(parsed) => SubjectQuota::active(word, id, parsed.space, parsed.inodes),
        Err(error) => SubjectQuota::unavailable(word, Some(id), error.reason_text()),
    }
}

fn read_subject(
    host: &QuotaHost,
    mount: &MountInfo,
    family: Family,
    id: u32,
) -> Result<Parsed, ProbeError> {
    tool::require_rooted_mount_point(mount)?;
    if host.check_magic {
        tool::verify_statfs(mount, NFS_SUPER_MAGIC)?;
    }
    let execution = run_quota(&host.quota, mount, family)?;
    let observed_at_unix =
        super::unix_time_now().map_err(|reason| super::incomplete(mount, reason))?;
    interpret(execution, mount, family, id, observed_at_unix)
}

fn run_quota(binary: &Path, mount: &MountInfo, family: Family) -> Result<Execution, ProbeError> {
    tool::capture(
        ToolRun {
            binary,
            tool: "quota",
            arguments: &[
                OsStr::new("-v"),
                OsStr::new("-w"),
                OsStr::new("-p"),
                OsStr::new("--show-mntpoint"),
                OsStr::new(family.flag()),
                OsStr::new("-f"),
                mount.mount_point.as_os_str(),
            ],
            timeout: QUOTA_TIMEOUT,
        },
        mount,
    )
}

/// The exit status is deliberately never read: see the module notes.
fn interpret(
    execution: Execution,
    mount: &MountInfo,
    family: Family,
    id: u32,
    observed_at_unix: u64,
) -> Result<Parsed, ProbeError> {
    if execution.stdout.truncated {
        return Err(super::incomplete(
            mount,
            "quota stdout exceeded the 64 KiB capture bound",
        ));
    }
    let stdout = String::from_utf8(execution.stdout.bytes)
        .map_err(|_| super::incomplete(mount, "quota stdout is not valid UTF-8"))?;
    let expected = ExpectedRow {
        source: mount
            .source
            .to_str()
            .ok_or_else(|| super::incomplete(mount, "mount source is not valid UTF-8"))?,
        mount_point: mount
            .mount_point
            .to_str()
            .ok_or_else(|| super::incomplete(mount, "mount point is not valid UTF-8"))?,
    };
    let parsed = parse(&stdout, &expected, family, id, observed_at_unix)
        .map_err(|reason| super::incomplete(mount, reason))?;
    parsed.ok_or_else(|| {
        let stderr = String::from_utf8_lossy(&execution.stderr.bytes);
        tool::unavailable(mount, refusal_reason(&stderr, family, id))
    })
}

/// What stderr said about this subject. The tool's lines end in the reason, as in
/// `quota: error while getting quota from server:/home for lab (id 1000): Connection refused`,
/// and the reason is all a report needs: it states the mount already.
fn refusal_reason(stderr: &str, family: Family, id: u32) -> String {
    let anchor = format!(" (id {id}): ");
    if let Some((_, reason)) = stderr.lines().find_map(|line| line.rsplit_once(&anchor)) {
        return reason_snippet(reason);
    }
    if stderr.trim().is_empty() {
        return format!(
            "quota printed no row for {} {id} on this mount",
            family.word()
        );
    }
    reason_snippet(stderr)
}

/// Strict grammar for `quota -v -w -p --show-mntpoint {-u|-g} -f <mount>`: one or
/// more blocks of a header, the column line and rows. `-g` prints a block per
/// group this process is in, and each is anchored by its id. `Ok(None)` means no
/// row answered for this subject. Anything unrecognized fails closed.
fn parse(
    stdout: &str,
    expected: &ExpectedRow<'_>,
    family: Family,
    id: u32,
    observed_at_unix: u64,
) -> Result<Option<Parsed>, String> {
    let mut lines = stdout.lines().peekable();
    let mut found = None;
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            continue;
        }
        let (block_id, has_rows) = parse_header(line, family)?;
        if !has_rows {
            continue;
        }
        let columns = lines
            .next()
            .ok_or_else(|| "output ended before the column header".to_owned())?;
        if columns.split_whitespace().collect::<Vec<_>>() != COLUMN_HEADER {
            return Err("line after the header is not a recognized column header".to_owned());
        }
        while let Some(row) = lines.next_if(|next| !next.starts_with(HEADER_PREFIX)) {
            if block_id != id || row.trim().is_empty() {
                continue;
            }
            if found.is_some() {
                return Err("quota printed more than one row for this mount".to_owned());
            }
            found = Some(parse_row(row, expected, observed_at_unix)?);
        }
    }
    Ok(found)
}

/// `Disk quotas for user <name> (uid N): ` with a trailing space, or ending in
/// `none` when there are no rows. The name is unvalidated; the anchor is what
/// binds the block to an id, so it is taken from the end of the line.
fn parse_header(line: &str, family: Family) -> Result<(u32, bool), String> {
    let label = family.id_label();
    let rest = line
        .strip_prefix(HEADER_PREFIX)
        .and_then(|rest| rest.strip_prefix(family.word()))
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(|| format!("line is not a {} quota header", family.word()))?;
    let (_, anchored) = rest
        .rsplit_once(&format!(" ({label} "))
        .ok_or_else(|| format!("quota header lacks a ({label} N): anchor"))?;
    let (digits, tail) = anchored
        .split_once("):")
        .ok_or_else(|| format!("quota header lacks a ({label} N): anchor"))?;
    let id = digits
        .parse()
        .map_err(|_| format!("quota header {label} is not numeric"))?;
    match tail.trim() {
        "" => Ok((id, true)),
        "none" => Ok((id, false)),
        _ => Err("quota header ends in something unrecognized".to_owned()),
    }
}

/// `<source> <mount point> <eight values>`. The values are taken from the end so a
/// mount point with spaces in it survives. The source and mount point are then
/// compared as one string, so a row has to name both.
fn parse_row(
    row: &str,
    expected: &ExpectedRow<'_>,
    observed_at_unix: u64,
) -> Result<Parsed, String> {
    let mut rest = row.trim_end();
    let mut values = [""; VALUE_COLUMN_COUNT];
    for slot in values.iter_mut().rev() {
        let split = rest.rfind(char::is_whitespace).ok_or_else(|| {
            format!("expected a source, a mount point and {VALUE_COLUMN_COUNT} value columns")
        })?;
        *slot = &rest[split + 1..];
        rest = rest[..split].trim_end();
    }
    let named_source = rest
        .strip_suffix(expected.mount_point)
        .and_then(|source| source.strip_suffix(' '))
        .ok_or_else(|| "row does not name the probed mount point".to_owned())?;
    if named_source != expected.source {
        return Err(format!(
            "row is for {named_source}, but the mount table has {} at this path",
            expected.source
        ));
    }
    let [
        blocks,
        block_soft,
        block_hard,
        block_grace,
        files,
        inode_soft,
        inode_hard,
        inode_grace,
    ] = values;
    let used_blocks = numeric_usage(blocks, "blocks")?;
    let soft_blocks = numeric_plain(block_soft, "block soft limit")?;
    let used_files = numeric_usage(files, "files")?;
    let soft_files = numeric_plain(inode_soft, "inode soft limit")?;
    let space = QuotaDimension::new(
        kib_to_bytes(used_blocks, "blocks")?,
        QuotaLimits::new(
            kib_to_bytes(soft_blocks, "block soft limit")?,
            kib_to_bytes(
                numeric_plain(block_hard, "block hard limit")?,
                "block hard limit",
            )?,
        ),
        row_grace(
            numeric_plain(block_grace, "block grace")?,
            used_blocks,
            soft_blocks,
            observed_at_unix,
        ),
    );
    let inodes = QuotaDimension::new(
        used_files,
        QuotaLimits::new(soft_files, numeric_plain(inode_hard, "inode hard limit")?),
        row_grace(
            numeric_plain(inode_grace, "inode grace")?,
            used_files,
            soft_files,
            observed_at_unix,
        ),
    );
    Ok(Parsed { space, inodes })
}

/// A grace column of zero means nothing is running, unless the row is over its soft
/// limit. quota-tools calls that over quota, because the deadline is not in the
/// future, and so does this: expired, with no deadline to report since none was given.
fn row_grace(deadline: u64, used: u64, soft: u64, observed_at_unix: u64) -> Option<QuotaGrace> {
    if deadline == 0 && soft != 0 && used > soft {
        return Some(QuotaGrace {
            state: QuotaGraceState::Expired,
            expires_at_unix: None,
        });
    }
    QuotaGrace::from_kernel_deadline(deadline, observed_at_unix)
}

#[cfg(test)]
mod tests {
    use super::{
        ExpectedRow, Family, Parsed, ProbeError, QuotaHost, group_quota, interpret, parse,
        refusal_reason, run_quota, survey,
    };
    use crate::quota::model::QuotaGraceState;
    use crate::quota::platform::MountInfo;
    use std::path::{Path, PathBuf};

    const UID: u32 = 1000;
    const GID: u32 = 2000;
    const OBSERVED_AT: u64 = 1_700_000_000;
    const MOUNT: &str = "/home";
    const SOURCE: &str = "nfs.example:/p2/home";
    const EXPECTED: ExpectedRow<'static> = ExpectedRow {
        source: SOURCE,
        mount_point: MOUNT,
    };
    const COLUMNS: &str =
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace";
    /// Real output from quota 4.05 against a VAST NFSv4.2 home, names replaced.
    const REAL_USER: &str = "Disk quotas for user researcher (uid 1000): \n     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\nnfs.example:/p2/home /home 19748892       0 105468748       0  156285  10000000 15000000       0\n";

    fn user_output(row: &str) -> String {
        format!("Disk quotas for user researcher (uid 1000): \n{COLUMNS}\n{row}\n")
    }

    fn parse_user(stdout: &str) -> Result<Option<Parsed>, String> {
        parse(stdout, &EXPECTED, Family::User, UID, OBSERVED_AT)
    }

    fn parse_error(stdout: &str) -> String {
        parse_user(stdout).map(|_| ()).unwrap_err()
    }

    #[test]
    fn real_row_reads_limits() {
        let parsed = parse_user(REAL_USER).unwrap().unwrap();
        assert_eq!(parsed.space.used, 19_748_892 * 1024);
        assert_eq!(parsed.space.soft_limit, None);
        assert_eq!(parsed.space.hard_limit, Some(105_468_748 * 1024));
        assert_eq!(parsed.inodes.used, 156_285);
        assert_eq!(parsed.inodes.soft_limit, Some(10_000_000));
        assert_eq!(parsed.inodes.hard_limit, Some(15_000_000));
        assert!(parsed.space.grace.is_none());
    }

    // The server answered, and it has no limit for this user. That is a fact,
    // unlike a missing row.
    #[test]
    fn zero_limits_mean_unlimited() {
        let stdout = user_output("nfs.example:/p2/home /home 5 0 0 0 7 0 0 0");
        let parsed = parse_user(&stdout).unwrap().unwrap();
        assert_eq!(parsed.space.hard_limit, None);
        assert_eq!(parsed.inodes.hard_limit, None);
    }

    #[test]
    fn over_limit_row_keeps_values() {
        let stdout = user_output(&format!(
            "nfs.example:/p2/home /home 300* 200 400 {} 9* 5 10 {}",
            OBSERVED_AT + 60,
            OBSERVED_AT - 60
        ));
        let parsed = parse_user(&stdout).unwrap().unwrap();
        assert_eq!(parsed.space.used, 300 * 1024);
        let grace = parsed.space.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Active);
        assert_eq!(grace.expires_at_unix, Some(OBSERVED_AT + 60));
        assert_eq!(parsed.inodes.used, 9);
        assert_eq!(parsed.inodes.grace.unwrap().state, QuotaGraceState::Expired);
    }

    #[test]
    fn missing_row_is_no_answer() {
        assert!(parse_user("").unwrap().is_none());
        let none = "Disk quotas for user researcher (uid 1000): none\n";
        assert!(parse_user(none).unwrap().is_none());
        let header_only = format!("Disk quotas for user researcher (uid 1000): \n{COLUMNS}\n");
        assert!(parse_user(&header_only).unwrap().is_none());
    }

    // `-g -f` prints one block per group, and only the one asked for counts.
    #[test]
    fn group_block_is_anchored() {
        let stdout = format!(
            "Disk quotas for group first (gid 1500): \n{COLUMNS}\nnfs.example:/p2/home /home 1 0 0 0 1 0 0 0\nDisk quotas for group second (gid 2000): \n{COLUMNS}\nnfs.example:/p2/home /home 8 0 16 0 1 0 0 0\n"
        );
        let parsed = parse(&stdout, &EXPECTED, Family::Group, GID, OBSERVED_AT)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.space.used, 8 * 1024);
        assert_eq!(parsed.space.hard_limit, Some(16 * 1024));
        let absent = parse(&stdout, &EXPECTED, Family::Group, 9, OBSERVED_AT).unwrap();
        assert!(absent.is_none());
    }

    #[test]
    fn user_block_for_another_uid_is_no_answer() {
        let stdout = REAL_USER.replace("(uid 1000)", "(uid 1001)");
        assert!(parse_user(&stdout).unwrap().is_none());
    }

    #[test]
    fn mount_point_with_spaces_survives() {
        let stdout = user_output("nfs.example:/x /mnt/my home 5 0 10 0 7 0 0 0");
        let expected = ExpectedRow {
            source: "nfs.example:/x",
            mount_point: "/mnt/my home",
        };
        let parsed = parse(&stdout, &expected, Family::User, UID, OBSERVED_AT)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.space.hard_limit, Some(10 * 1024));
    }

    #[test]
    fn row_for_another_mount_fails() {
        for row in [
            "nfs.example:/p2/tools /tools 5 0 0 0 7 0 0 0",
            "/home 5 0 0 0 7 0 0 0",
            "nfs.example:/p2/home2 /home2 5 0 0 0 7 0 0 0",
        ] {
            let reason = parse_error(&user_output(row));
            assert!(reason.contains("mount point"), "{row}: {reason}");
        }
    }

    // One mount on top of another at the same path: the tool can ask the server
    // underneath and still print the path. The source is what gives it away.
    #[test]
    fn same_path_other_source_fails() {
        for row in [
            "other.example:/p2/home /home 5 0 0 0 7 0 0 0",
            "nfs.example:/p2/home2 /home 5 0 0 0 7 0 0 0",
            "nfs.example:/x /x /home 5 0 0 0 7 0 0 0",
            " /home 5 0 0 0 7 0 0 0",
        ] {
            assert!(parse_user(&user_output(row)).is_err(), "{row}");
        }
        let reason = parse_error(&user_output("other.example:/p2/home /home 5 0 0 0 7 0 0 0"));
        assert!(reason.contains("other.example:/p2/home"), "{reason}");
        assert!(
            reason.contains("the mount table has nfs.example:/p2/home"),
            "{reason}"
        );
    }

    // A missing column shifts the mount point into the values, so it cannot pass.
    #[test]
    fn missing_column_fails() {
        for row in [
            "nfs.example:/p2/home /home 5 0 0 0 7 0 0",
            "5 0 0",
            "nfs.example:/p2/home /home 5 0 0 0 7 0 0 0 9",
        ] {
            assert!(parse_user(&user_output(row)).is_err(), "{row}");
        }
    }

    #[test]
    fn bad_values_fail() {
        for (row, expected) in [
            ("nfs.example:/p2/home /home x 0 0 0 7 0 0 0", "blocks"),
            ("nfs.example:/p2/home /home 5 0* 0 0 7 0 0 0", "block soft"),
            ("nfs.example:/p2/home /home 5 0 0 1w 7 0 0 0", "block grace"),
            ("nfs.example:/p2/home /home 5M 0 0 0 7 0 0 0", "blocks"),
            (
                "nfs.example:/p2/home /home 18446744073709551615 0 0 0 7 0 0 0",
                "overflows",
            ),
        ] {
            let reason = parse_error(&user_output(row));
            assert!(reason.contains(expected), "{row}: {reason}");
        }
    }

    #[test]
    fn unrecognized_output_fails() {
        for (stdout, expected) in [
            ("something else\n".to_owned(), "not a user quota header"),
            (
                "Disk quotas for group x (gid 1): \n".to_owned(),
                "not a user quota header",
            ),
            ("Disk quotas for user x: \n".to_owned(), "anchor"),
            (
                "Disk quotas for user x (uid abc): \n".to_owned(),
                "not numeric",
            ),
            (
                "Disk quotas for user x (uid 1): maybe\n".to_owned(),
                "unrecognized",
            ),
            (
                "Disk quotas for user x (uid 1000): \n".to_owned(),
                "before the column",
            ),
            (
                "Disk quotas for user x (uid 1000): \nFilesystem used\n".to_owned(),
                "column header",
            ),
            (
                format!(
                    "Disk quotas for user x (uid 1000): \n{COLUMNS}\nnfs.example:/p2/home /home 1 0 0 0 1 0 0 0\nnfs.example:/p2/home /home 1 0 0 0 1 0 0 0\n"
                ),
                "more than one row",
            ),
        ] {
            let reason = parse_error(&stdout);
            assert!(reason.contains(expected), "{stdout:?}: {reason}");
        }
    }

    // A hostile group name cannot supply the anchor.
    #[test]
    fn name_cannot_fake_anchor() {
        let stdout = format!(
            "Disk quotas for group x (gid 2000): (gid 1500): \n{COLUMNS}\nnfs.example:/p2/home /home 8 0 0 0 1 0 0 0\n"
        );
        let absent = parse(&stdout, &EXPECTED, Family::Group, GID, OBSERVED_AT).unwrap();
        assert!(absent.is_none());
    }

    #[test]
    fn refusal_names_the_server_reason() {
        let stderr = "quota: error while getting quota from nfs.example:/p2/home for other (id 1500): Connection refused\nquota: error while getting quota from nfs.example:/p2/home for lab (id 2000): Timed out\n";
        assert_eq!(refusal_reason(stderr, Family::Group, GID), "Timed out");
        // No line about this id: the rest of stderr is still all there is to say.
        let reason = refusal_reason(
            "quota: Cannot initialize mountpoint scan.\n",
            Family::Group,
            GID,
        );
        assert!(reason.contains("Cannot initialize"), "{reason}");
        let reason = refusal_reason("", Family::Group, GID);
        assert!(reason.contains("no row for group 2000"), "{reason}");
    }

    fn stub(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        // Held across the write: a fork in another thread would inherit this
        // descriptor and the exec below would then see a writer.
        let _exclusive = crate::fork_gate::exec_fresh_file();
        let path = dir.join("quota-stub.sh");
        std::fs::write(&path, body).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn stubbed(body: &str, family: Family, id: u32) -> Result<Parsed, ProbeError> {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(dir.path(), body);
        let mount = MountInfo {
            mount_point: PathBuf::from(MOUNT),
            ..nfs_mount()
        };
        let execution = run_quota(&script, &mount, family).unwrap();
        interpret(execution, &mount, family, id, OBSERVED_AT)
    }

    #[test]
    fn asks_about_this_mount_only() {
        let dir = tempfile::tempdir().unwrap();
        let script = stub(dir.path(), "#!/bin/sh\necho \"$*\"\n");
        let mount = MountInfo {
            mount_point: PathBuf::from(MOUNT),
            ..nfs_mount()
        };
        for (family, flag) in [(Family::User, "-u"), (Family::Group, "-g")] {
            let execution = run_quota(&script, &mount, family).unwrap();
            assert_eq!(
                String::from_utf8(execution.stdout.bytes).unwrap(),
                format!("-v -w -p --show-mntpoint {flag} -f /home\n")
            );
        }
    }

    // `quota` exits non-zero when a limit is exceeded. That is the moment this
    // report matters most, so the status cannot be what decides.
    #[test]
    fn over_limit_exit_keeps_the_row() {
        let body = "#!/bin/sh\nprintf 'Disk quotas for user x (uid 1000): \\n%s\\nnfs.example:/p2/home /home 300* 200 400 0 9 0 0 0\\n' 'Filesystem blocks quota limit grace files quota limit grace'\nexit 1\n";
        let parsed = stubbed(body, Family::User, UID).unwrap();
        assert_eq!(parsed.space.used, 300 * 1024);
        assert_eq!(parsed.space.hard_limit, Some(400 * 1024));
        // A zero grace column over the soft limit: quota-tools calls this over quota.
        let grace = parsed.space.grace.unwrap();
        assert_eq!(grace.state, QuotaGraceState::Expired);
        assert_eq!(grace.expires_at_unix, None);
    }

    #[test]
    fn zero_grace_reads_with_the_soft_limit() {
        // Over the soft limit: expired, with no deadline made up.
        let over = parse_user(&user_output(
            "nfs.example:/p2/home /home 300* 200 400 0 9* 5 10 0",
        ))
        .unwrap()
        .unwrap();
        let block = over.space.grace.unwrap();
        assert_eq!(block.state, QuotaGraceState::Expired);
        assert_eq!(block.expires_at_unix, None);
        let inode = over.inodes.grace.unwrap();
        assert_eq!(inode.state, QuotaGraceState::Expired);
        assert_eq!(inode.expires_at_unix, None);
        // At the soft limit is not over it, and no soft limit has nothing to be over.
        let at = parse_user(&user_output(
            "nfs.example:/p2/home /home 200 200 400 0 5 5 10 0",
        ))
        .unwrap()
        .unwrap();
        assert!(at.space.grace.is_none() && at.inodes.grace.is_none());
        let none = parse_user(&user_output(
            "nfs.example:/p2/home /home 300 0 400 0 9 0 10 0",
        ))
        .unwrap()
        .unwrap();
        assert!(none.space.grace.is_none() && none.inodes.grace.is_none());
    }

    // And it exits zero when the server refused, with nothing on stdout for the
    // mount: the shape a real VAST server gives for a group.
    #[test]
    fn refused_with_exit_zero_is_unavailable() {
        let body = "#!/bin/sh\necho 'quota: error while getting quota from nfs.example:/h for lab (id 2000): Connection refused' >&2\nprintf 'Disk quotas for group lab (gid 2000): none\\n'\nexit 0\n";
        let error = stubbed(body, Family::Group, GID).map(|_| ()).unwrap_err();
        let ProbeError::Unavailable { reason, .. } = error else {
            panic!("a refused query must be unavailable: {error:?}");
        };
        assert_eq!(reason, "Connection refused");
    }

    #[test]
    fn empty_failure_is_unavailable() {
        let body = "#!/bin/sh\necho 'quota: Cannot initialize mountpoint scan.' >&2\nexit 2\n";
        let error = stubbed(body, Family::User, UID).map(|_| ()).unwrap_err();
        assert!(matches!(error, ProbeError::Unavailable { .. }), "{error:?}");
    }

    #[test]
    fn missing_tool_is_unavailable() {
        let mount = nfs_mount();
        let error = run_quota(
            Path::new("/nonexistent/degu-test-quota"),
            &mount,
            Family::User,
        )
        .map(|_| ())
        .unwrap_err();
        let ProbeError::Unavailable { reason, .. } = error else {
            panic!("a missing tool must be unavailable: {error:?}");
        };
        assert!(reason.contains("/nonexistent/degu-test-quota"), "{reason}");
    }

    #[test]
    fn garbage_row_is_incomplete() {
        let body = "#!/bin/sh\nprintf 'Disk quotas for user x (uid 1000): \\nnot columns\\n'\n";
        let error = stubbed(body, Family::User, UID).map(|_| ()).unwrap_err();
        assert!(matches!(error, ProbeError::Incomplete { .. }), "{error:?}");
    }

    fn nfs_mount() -> MountInfo {
        MountInfo {
            mount_point: PathBuf::from("/"),
            filesystem: "nfs4".to_owned(),
            source: PathBuf::from(SOURCE),
            mount_id: 40,
            device_major: 0,
            device_minor: 64,
        }
    }

    fn home_mount() -> MountInfo {
        MountInfo {
            mount_point: PathBuf::from(MOUNT),
            ..nfs_mount()
        }
    }

    /// A stand-in `quota` answering the way the real one does for a user, with the
    /// group query's behaviour left to the caller.
    fn stand_in(group_answer: &str) -> (tempfile::TempDir, QuotaHost) {
        let dir = tempfile::tempdir().unwrap();
        stub(
            dir.path(),
            &format!(
                "#!/bin/sh\ncase \"$5\" in\n-u) printf 'Disk quotas for user x (uid 1000): \\n%s\\nnfs.example:/p2/home /home 8 0 16 0 1 0 0 0\\n' 'Filesystem blocks quota limit grace files quota limit grace' ;;\n-g) {group_answer} ;;\nesac\n"
            ),
        );
        std::fs::rename(dir.path().join("quota-stub.sh"), dir.path().join("quota")).unwrap();
        let host = QuotaHost::standing_in(dir.path());
        (dir, host)
    }

    // The shape the validated server gives: the user answers, the group is refused.
    #[test]
    fn survey_keeps_a_refused_group() {
        let (_dir, host) = stand_in(
            "echo 'quota: error while getting quota from nfs.example:/p2/home for lab (id 2000): Connection refused' >&2",
        );
        let report = survey(&host, home_mount(), Path::new("/home/me"), UID, Ok(GID)).unwrap();
        assert_eq!(report.provider, "nfs_rquota");
        assert_eq!(report.space.hard_limit, Some(16 * 1024));
        let group = &report.other_subjects[0];
        assert_eq!((group.kind, group.id), ("group", Some(GID)));
        assert_eq!(group.state, "unavailable");
        assert_eq!(group.reason.as_deref(), Some("Connection refused"));
        assert!(!report.limits_complete);
    }

    #[test]
    fn survey_reports_unknown_group() {
        let (_dir, host) = stand_in("echo 'must not be asked' >&2; exit 1");
        let report = survey(
            &host,
            home_mount(),
            Path::new("/home/me"),
            UID,
            Err("Permission denied".to_owned()),
        )
        .unwrap();
        let group = &report.other_subjects[0];
        assert_eq!((group.kind, group.id), ("group", None));
        assert_eq!(group.reason.as_deref(), Some("Permission denied"));
        assert!(!report.limits_complete);
    }

    #[test]
    fn group_failure_is_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let quota = group_quota(&QuotaHost::standing_in(dir.path()), &home_mount(), GID);
        assert_eq!(quota.kind, "group");
        assert_eq!(quota.id, Some(GID));
        assert_eq!(quota.state, "unavailable");
        assert!(quota.reason.as_deref().is_some_and(|text| !text.is_empty()));
        assert!(quota.space.is_none() && quota.inodes.is_none());
    }

    // The user's own answer is what the report stands on, so losing it is an error.
    #[test]
    fn user_failure_stays_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = survey(
            &QuotaHost::standing_in(dir.path()),
            home_mount(),
            Path::new("/home/me"),
            UID,
            Ok(GID),
        )
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(error, ProbeError::Unavailable { .. }), "{error:?}");
    }
}
