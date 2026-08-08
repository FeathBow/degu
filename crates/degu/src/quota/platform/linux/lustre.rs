//! Lustre user quota provider backed by the `lfs` client tool.
//!
//! There is no stable kernel ABI for Lustre quota queries, so this provider
//! executes `/usr/bin/lfs quota` and parses its stdout under a strict
//! whole-output grammar. Any deviation from that grammar fails closed with an
//! honest error instead of risking a wrong number.
//!
//! Threat boundary: the exec hardening below (absolute binary path, cleared
//! environment, pinned C locale, neutral working directory, closed stdin,
//! bounded concurrent output capture, bounded timeout, escaped error text)
//! defends against confusion: PATH or environment injection, locale drift,
//! hostile bytes in the output stream, and Lustre servers that hang. It does
//! not defend against a hostile root: whoever controls /usr/bin/lfs already
//! controls this process's view of the filesystem. One residual is accepted:
//! the in-process statfs cross-check and path canonicalization below run
//! before the time-bounded child and can still block on a mount whose
//! servers are unresponsive — degu then hangs honestly rather than printing
//! a number it could not verify.

use super::{MountInfo, ProbeError};
use crate::quota::model::{
    ActiveQuota, QuotaDimension, QuotaGrace, QuotaGraceState, QuotaLimits, QuotaSnapshot,
};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PROVIDER: &str = "lustre_lfs";
const DATA_SOURCE: &str = "lfs_quota";
pub(super) const FILESYSTEM: &str = "lustre";
/// The only binary this provider will ever execute. No PATH resolution and
/// no fallback locations: a missing tool is an honest Unavailable error.
const LFS_BINARY: &str = "/usr/bin/lfs";
const LUSTRE_SUPER_MAGIC: u64 = 0x0BD0_0BD0;
/// Linux `f_type` has arch-dependent signedness and width; every known magic
/// value is 32-bit, so comparisons mask to the low 32 bits first. This is the
/// same trick as degu-walk's fstype module, reimplemented locally because
/// that module is private to degu-walk.
const LINUX_F_TYPE_MASK: u64 = u32::MAX as u64;
/// Per-stream capture bound; output beyond it makes the probe Incomplete.
const OUTPUT_CAP_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 4096;
const LFS_TIMEOUT: Duration = Duration::from_secs(10);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_COLLECT_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const KIB: u64 = 1024;
const QUOTAS_NOT_ENABLED_MARKER: &str = "quotas are not enabled";
/// Reasons surface on stderr; keep hostile or verbose lfs output bounded.
/// The display layer escapes terminal controls, so truncation is the only
/// concern here.
const STDERR_REASON_CHAR_CAP: usize = 200;
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

#[derive(Debug)]
struct Execution {
    status: ExitStatus,
    stdout: CappedStream,
    stderr: CappedStream,
}

#[derive(Debug)]
struct CappedStream {
    bytes: Vec<u8>,
    truncated: bool,
}

pub(super) fn probe(
    mount: MountInfo,
    path: &Path,
    subject_id: u32,
) -> Result<QuotaSnapshot, ProbeError> {
    require_rooted_mount_point(&mount)?;
    verify_statfs_is_lustre(&mount)?;
    let execution = capture(Path::new(LFS_BINARY), &mount, subject_id, LFS_TIMEOUT)?;
    let stdout = successful_stdout(&mount, execution)?;
    // Sampled right after lfs exits, so it sits closest to the instant the
    // server produced the countdown that expires_at_unix is derived from.
    let observed_at_unix =
        super::unix_time_now().map_err(|reason| super::incomplete(&mount, reason))?;
    let parsed = parse(&stdout, &mount.mount_point, subject_id, observed_at_unix)
        .map_err(|reason| super::incomplete(&mount, reason))?;
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

/// The mount point is handed to lfs as a positional argument; require an
/// absolute path so a mangled mountinfo entry can never smuggle an
/// option-like or relative argument into the child process.
fn require_rooted_mount_point(mount: &MountInfo) -> Result<(), ProbeError> {
    if mount.mount_point.as_os_str().as_bytes().starts_with(b"/") {
        return Ok(());
    }
    Err(super::incomplete(
        mount,
        "mount point is not an absolute path",
    ))
}

/// Cross-check: mountinfo said "lustre"; require the kernel's statfs magic to
/// agree before executing lfs against this mount point.
fn verify_statfs_is_lustre(mount: &MountInfo) -> Result<(), ProbeError> {
    let stat = rustix::fs::statfs(&mount.mount_point).map_err(|error| {
        super::incomplete(mount, format!("statfs failed for the mount point: {error}"))
    })?;
    let magic = stat.f_type as u64 & LINUX_F_TYPE_MASK;
    if magic != LUSTRE_SUPER_MAGIC {
        return Err(super::incomplete(
            mount,
            format!("mountinfo reports lustre but the statfs magic is {magic:#x}"),
        ));
    }
    Ok(())
}

fn capture(
    binary: &Path,
    mount: &MountInfo,
    euid: u32,
    timeout: Duration,
) -> Result<Execution, ProbeError> {
    let mut child = spawn_lfs(binary, mount, euid)?;
    // Read both pipes concurrently on dedicated threads: a child that fills
    // stderr while the parent drains only stdout (or vice versa) would
    // deadlock against a full pipe buffer. The threads are never joined; on
    // the failure paths below they stay parked on a read until this
    // short-lived process exits.
    let stdout_stream = child.stdout.take().expect("stdout is piped at spawn");
    let stderr_stream = child.stderr.take().expect("stderr is piped at spawn");
    let stdout_receiver = spawn_capped_reader(stdout_stream);
    let stderr_receiver = spawn_capped_reader(stderr_stream);
    let status = await_exit(&mut child, mount, timeout)?;
    // The pipes normally close when the child exits, but lfs could have
    // leaked its descriptors to a grandchild that keeps them open; bound the
    // wait and abandon the reader instead of hanging.
    let stdout = collect_stream(&stdout_receiver).ok_or_else(|| {
        unavailable(
            mount,
            "lfs exited but its stdout pipe stayed open".to_owned(),
        )
    })?;
    let stderr = collect_stream(&stderr_receiver).ok_or_else(|| {
        unavailable(
            mount,
            "lfs exited but its stderr pipe stayed open".to_owned(),
        )
    })?;
    Ok(Execution {
        status,
        stdout,
        stderr,
    })
}

fn spawn_lfs(binary: &Path, mount: &MountInfo, euid: u32) -> Result<Child, ProbeError> {
    // Hardened exec: absolute path only, no shell, argv fixed to
    // ["quota", "-u", <numeric euid>, <mount point>], an emptied environment
    // with a pinned C locale, a neutral working directory, and closed stdin.
    Command::new(binary)
        .arg("quota")
        .arg("-u")
        .arg(euid.to_string())
        .arg(&mount.mount_point)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| spawn_error(binary, mount, &error))
}

fn spawn_error(binary: &Path, mount: &MountInfo, error: &std::io::Error) -> ProbeError {
    let reason = if error.kind() == std::io::ErrorKind::NotFound {
        format!("the lfs client tool is not present at {}", binary.display())
    } else {
        format!("failed to launch {}: {error}", binary.display())
    };
    unavailable(mount, reason)
}

fn spawn_capped_reader(stream: impl Read + Send + 'static) -> mpsc::Receiver<CappedStream> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        // A dropped receiver on the timeout path makes this send fail; the
        // capture is discarded on purpose there.
        let _ = sender.send(read_capped(stream));
    });
    receiver
}

fn read_capped(mut stream: impl Read) -> CappedStream {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let capacity_left = OUTPUT_CAP_BYTES - bytes.len();
                if count > capacity_left {
                    truncated = true;
                }
                bytes.extend_from_slice(&chunk[..count.min(capacity_left)]);
                // Keep draining past the bound so the child never blocks on a
                // full pipe; the excess is discarded and the probe fails
                // closed on `truncated`.
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            // A read error means the capture cannot be trusted to be
            // complete; fail closed the same way as an over-bound stream.
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    CappedStream { bytes, truncated }
}

fn collect_stream(receiver: &mpsc::Receiver<CappedStream>) -> Option<CappedStream> {
    receiver.recv_timeout(OUTPUT_COLLECT_TIMEOUT).ok()
}

fn await_exit(
    child: &mut Child,
    mount: &MountInfo,
    timeout: Duration,
) -> Result<ExitStatus, ProbeError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                abandon(child);
                return Err(unavailable(
                    mount,
                    format!("failed to monitor the lfs process: {error}"),
                ));
            }
        }
        if Instant::now() >= deadline {
            abandon(child);
            return Err(unavailable(mount, "lfs quota timed out".to_owned()));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Kill, then reap within a bounded window. A Lustre client stuck in
/// uninterruptible I/O (D state) can outlive SIGKILL indefinitely; a blocking
/// `wait()` here could hang degu forever, so after the window the child is
/// abandoned unreaped. degu exits shortly afterwards and init adopts and
/// reaps the orphan; a lingering D-state process is the accepted residual.
fn abandon(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + REAP_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
        }
    }
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

fn reason_snippet(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return "no stderr output".to_owned();
    }
    let mut snippet: String = trimmed.chars().take(STDERR_REASON_CHAR_CAP).collect();
    if snippet.len() < trimmed.len() {
        snippet.push_str("...");
    }
    snippet
}

fn unavailable(mount: &MountInfo, reason: String) -> ProbeError {
    ProbeError::Unavailable {
        filesystem: mount.filesystem.clone(),
        mount_point: mount.mount_point.display().to_string(),
        reason,
    }
}

/// Strict whole-output grammar for `lfs quota -u <euid> <mount point>`.
///
/// Pure function: no process state, unit-testable with fixture text. Every
/// deviation returns a line-specific Incomplete reason; nothing is guessed.
fn parse(
    stdout: &str,
    mount_point: &Path,
    euid: u32,
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
        euid,
    )?;
    parse_column_header(
        lines
            .next()
            .ok_or_else(|| "output ended before the column header".to_owned())?,
    )?;
    let columns = parse_data_row(&mut lines, mount_text)?;
    let parsed = parse_columns(columns, observed_at_unix)?;
    parse_trailers(lines, euid)?;
    Ok(parsed)
}

/// Line 1: `Disk quotas for usr <name> (uid N):`. Vanilla builds print `usr`
/// and some builds print `user`; the name field is unvalidated, but the
/// trailing `(uid N):` anchor must match the probed euid exactly.
fn parse_header(line: &str, euid: u32) -> Result<(), IncompleteReason> {
    let rest = line
        .strip_prefix("Disk quotas for usr ")
        .or_else(|| line.strip_prefix("Disk quotas for user "))
        .ok_or_else(|| "first line is not a user quota header".to_owned())?;
    // Anchor on the last " (uid " so a hostile user name cannot fake it.
    let (_, uid_text) = rest
        .rsplit_once(" (uid ")
        .ok_or_else(|| "quota header lacks a (uid N): anchor".to_owned())?;
    let digits = uid_text
        .strip_suffix("):")
        .ok_or_else(|| "quota header lacks a (uid N): anchor".to_owned())?;
    let uid: u32 = digits
        .parse()
        .map_err(|_| "quota header uid is not numeric".to_owned())?;
    if uid != euid {
        return Err(format!("quota header reports uid {uid}, expected {euid}"));
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

/// Numeric columns are plain unsigned integers, optionally carrying one
/// trailing `*`. With exit status zero as a precondition the marker is a
/// genuine over-limit flag, so it is stripped without further semantics.
/// Everything else -- bracketed `[N]` placeholders, signs, empty tokens --
/// fails closed.
/// A trailing `*` is lfs's over-limit marker on the usage columns only; a
/// starred limit is not lfs grammar and fails closed.
fn numeric_usage(token: &str, column: &str) -> Result<u64, IncompleteReason> {
    numeric_plain(token.strip_suffix('*').unwrap_or(token), column)
}

fn numeric_plain(token: &str, column: &str) -> Result<u64, IncompleteReason> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{column} column is not an unsigned integer"));
    }
    token
        .parse()
        .map_err(|_| format!("{column} column does not fit in 64 bits"))
}

fn kib_to_bytes(value: u64, column: &str) -> Result<u64, IncompleteReason> {
    value
        .checked_mul(KIB)
        .ok_or_else(|| format!("{column} column overflows when converted to bytes"))
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
/// when the uid has no explicitly configured limits. Anything else after the
/// data row -- a second usr/grp block, an error trailer -- fails closed.
fn parse_trailers(lines: std::str::Lines<'_>, euid: u32) -> Result<(), IncompleteReason> {
    let expected = [
        format!("uid {euid} is using default block quota setting"),
        format!("uid {euid} is using default file quota setting"),
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
    use super::{
        CappedStream, Execution, LFS_TIMEOUT, MountInfo, Parsed, ProbeError, QuotaGraceState,
        capture, countdown_seconds, parse, require_rooted_mount_point, successful_stdout,
        verify_statfs_is_lustre,
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
        parse(stdout, Path::new(MOUNT), EUID, OBSERVED_AT)
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
            EUID,
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
        let parsed = parse(&stdout, Path::new("/mnt/my scratch"), EUID, OBSERVED_AT).unwrap();
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
        }
    }

    fn stub(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
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

    // A parallel test's fork can briefly hold a write handle to a freshly written
    // stub, so its exec races ETXTBSY; retry until the sibling exec clears it.
    fn capture_stub(
        script: &Path,
        mount: &MountInfo,
        timeout: Duration,
    ) -> Result<Execution, ProbeError> {
        for _ in 0..100 {
            match capture(script, mount, EUID, timeout) {
                Err(ProbeError::Unavailable { reason, .. })
                    if reason.contains("Text file busy") =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                result => return result,
            }
        }
        capture(script, mount, EUID, timeout)
    }

    #[test]
    fn lustre_exec_missing_binary_is_unavailable_and_names_the_path() {
        let error = capture(
            Path::new("/nonexistent/degu-test-lfs"),
            &test_mount(),
            EUID,
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
        let execution = capture_stub(&script, &mount, LFS_TIMEOUT).unwrap();
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
        let execution = capture_stub(&script, &mount, LFS_TIMEOUT).unwrap();
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
        let error = capture_stub(&script, &test_mount(), Duration::from_millis(200)).unwrap_err();
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
        let execution = capture_stub(&script, &mount, LFS_TIMEOUT).unwrap();
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
        };
        let error = verify_statfs_is_lustre(&mount).unwrap_err();
        assert!(matches!(error, ProbeError::Incomplete { .. }), "{error:?}");
    }

    #[test]
    fn lustre_relative_mount_points_fail_closed_before_exec() {
        let mount = MountInfo {
            mount_point: PathBuf::from("scratch"),
            filesystem: "lustre".to_owned(),
            source: PathBuf::from("10.0.0.1@tcp:/scratch"),
        };
        let error = require_rooted_mount_point(&mount).unwrap_err();
        assert!(matches!(error, ProbeError::Incomplete { .. }), "{error:?}");
    }
}
