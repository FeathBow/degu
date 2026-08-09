mod lustre;

use super::{MountInfo, ProbeError};
use crate::quota::model::{ActiveQuota, QuotaDimension, QuotaGrace, QuotaLimits, QuotaSnapshot};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PROVIDER: &str = "linux_vfs";
const DATA_SOURCE: &str = "linux_quotactl";
const QUOTA_BLOCK_BYTES: u64 = 1024;
const SUPPORTED_FILESYSTEM: &str = "ext4";
const SUBCOMMAND_SHIFT: u32 = 8;
const OCTAL_DIGIT_COUNT: usize = 3;
const OCTAL_RADIX: u32 = 8;
const REQUIRED_VALID_FIELDS: u32 = libc::QIF_LIMITS | libc::QIF_USAGE | libc::QIF_TIMES;

#[derive(Debug)]
struct QueryResult {
    space: QuotaDimension,
    inodes: QuotaDimension,
}

pub(super) fn probe(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    let mount = inspect_mount(path)?;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let subject_id = unsafe { libc::geteuid() };
    let snapshot = match mount.filesystem.as_str() {
        SUPPORTED_FILESYSTEM => probe_vfs(mount.clone(), path, subject_id),
        lustre::FILESYSTEM => lustre::probe(mount.clone(), path, subject_id),
        _ => Err(unsupported(&mount)),
    }?;
    // Detect ordinary concurrent replacement. A privileged mount controller can
    // still arrange A -> B -> the same A; that hostile-root ABA is outside this
    // reporting-only provider's threat boundary (see the Lustre module notes).
    let rebound = inspect_mount(path)?;
    if rebound != mount {
        return Err(incomplete(
            &mount,
            "mount identity changed during quota probe",
        ));
    }
    Ok(snapshot)
}

fn probe_vfs(mount: MountInfo, path: &Path, subject_id: u32) -> Result<QuotaSnapshot, ProbeError> {
    let result = query_current_user(&mount, subject_id)?;
    let scope = mount.scope(path);
    Ok(QuotaSnapshot::active(
        scope,
        subject_id,
        ActiveQuota {
            provider: PROVIDER,
            data_source: DATA_SOURCE,
            space: result.space,
            inodes: result.inodes,
        },
    ))
}

fn inspect_mount(path: &Path) -> Result<MountInfo, ProbeError> {
    let mountinfo =
        std::fs::read_to_string("/proc/self/mountinfo").map_err(|source| ProbeError::Io {
            path: "/proc/self/mountinfo".to_owned(),
            source,
        })?;
    parse_mountinfo(&mountinfo, path).ok_or_else(|| ProbeError::Incomplete {
        filesystem: "unknown".to_owned(),
        mount_point: path.display().to_string(),
        reason: "target path is absent from /proc/self/mountinfo".to_owned(),
    })
}

fn parse_mountinfo(input: &str, path: &Path) -> Option<MountInfo> {
    input
        .lines()
        .filter_map(parse_mount_line)
        .filter(|mount| path.starts_with(&mount.mount_point))
        .max_by_key(|mount| mount.mount_point.as_os_str().len())
}

fn parse_mount_line(line: &str) -> Option<MountInfo> {
    let (mount, filesystem) = line.split_once(" - ")?;
    let mut mount_fields = mount.split_whitespace();
    let mount_id = mount_fields.next()?.parse().ok()?;
    let _parent_id = mount_fields.next()?;
    let device = mount_fields.next()?;
    let (device_major, device_minor) = device.split_once(':')?;
    let device_major = device_major.parse().ok()?;
    let device_minor = device_minor.parse().ok()?;
    let _root = mount_fields.next()?;
    let mount_point = mount_fields.next()?;
    let mut fields = filesystem.split_whitespace();
    let filesystem = fields.next()?.to_owned();
    let source = fields.next()?;
    Some(MountInfo {
        mount_point: decode_path(mount_point),
        filesystem,
        source: decode_path(source),
        mount_id,
        device_major,
        device_minor,
    })
}

fn decode_path(value: &str) -> PathBuf {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some((byte, consumed)) = decode_escape(&bytes[index..]) {
            decoded.push(byte);
            index += consumed;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    PathBuf::from(OsString::from_vec(decoded))
}

fn decode_escape(bytes: &[u8]) -> Option<(u8, usize)> {
    let (&prefix, remaining) = bytes.split_first()?;
    if prefix != b'\\' || remaining.len() < OCTAL_DIGIT_COUNT {
        return None;
    }
    let digits = &remaining[..OCTAL_DIGIT_COUNT];
    if !digits.iter().all(|digit| matches!(digit, b'0'..=b'7')) {
        return None;
    }
    let encoded = std::str::from_utf8(digits).ok()?;
    let value = u8::from_str_radix(encoded, OCTAL_RADIX).ok()?;
    Some((value, OCTAL_DIGIT_COUNT + 1))
}

fn query_current_user(mount: &MountInfo, subject_id: u32) -> Result<QueryResult, ProbeError> {
    let source = CString::new(mount.source.as_os_str().as_bytes())
        .map_err(|_| incomplete(mount, "mount source contains a NUL byte"))?;
    let kernel_subject_id = quotactl_subject_id(subject_id);
    // SAFETY: dqblk is a plain C output structure and zero is a valid initialization.
    let mut raw = unsafe { std::mem::zeroed::<libc::dqblk>() };
    // SAFETY: pointers remain valid for the call and reference writable dqblk storage.
    let result = unsafe {
        libc::quotactl(
            quota_command(),
            source.as_ptr(),
            kernel_subject_id,
            std::ptr::addr_of_mut!(raw).cast::<libc::c_char>(),
        )
    };
    if result == 0 {
        let observed_at_unix = unix_time_now().map_err(|reason| incomplete(mount, reason))?;
        return normalize(raw, observed_at_unix).map_err(|reason| incomplete(mount, reason));
    }
    classify_error(mount, std::io::Error::last_os_error())
}

fn quotactl_subject_id(subject_id: u32) -> libc::c_int {
    // libc exposes c_int, but Linux consumes its bits as qid_t.
    subject_id.cast_signed()
}

fn quota_command() -> libc::c_int {
    (((libc::Q_GETQUOTA as u32) << SUBCOMMAND_SHIFT) | libc::USRQUOTA as u32) as libc::c_int
}

fn normalize(raw: libc::dqblk, observed_at_unix: u64) -> Result<QueryResult, &'static str> {
    if raw.dqb_valid & REQUIRED_VALID_FIELDS != REQUIRED_VALID_FIELDS {
        return Err("kernel response omitted usage, limit, or grace fields");
    }
    Ok(QueryResult {
        space: QuotaDimension::new(
            raw.dqb_curspace,
            QuotaLimits::new(
                quota_bytes(raw.dqb_bsoftlimit)?,
                quota_bytes(raw.dqb_bhardlimit)?,
            ),
            QuotaGrace::from_kernel_deadline(raw.dqb_btime, observed_at_unix),
        ),
        inodes: QuotaDimension::new(
            raw.dqb_curinodes,
            QuotaLimits::new(raw.dqb_isoftlimit, raw.dqb_ihardlimit),
            QuotaGrace::from_kernel_deadline(raw.dqb_itime, observed_at_unix),
        ),
    })
}

fn unix_time_now() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch")
}

fn quota_bytes(blocks: u64) -> Result<u64, &'static str> {
    blocks
        .checked_mul(QUOTA_BLOCK_BYTES)
        .ok_or("quota block limit overflows bytes")
}

fn classify_error(mount: &MountInfo, error: std::io::Error) -> Result<QueryResult, ProbeError> {
    match error.raw_os_error() {
        Some(libc::ESRCH) => Err(ProbeError::NotConfigured {
            filesystem: mount.filesystem.clone(),
            mount_point: mount.mount_point.display().to_string(),
        }),
        Some(libc::EACCES | libc::EPERM) => Err(ProbeError::PermissionDenied {
            filesystem: mount.filesystem.clone(),
            mount_point: mount.mount_point.display().to_string(),
            reason: error.to_string(),
        }),
        Some(libc::ENOENT | libc::ENOSYS | libc::EOPNOTSUPP) => Err(ProbeError::Unavailable {
            filesystem: mount.filesystem.clone(),
            mount_point: mount.mount_point.display().to_string(),
            reason: error.to_string(),
        }),
        _ => Err(ProbeError::Unavailable {
            filesystem: mount.filesystem.clone(),
            mount_point: mount.mount_point.display().to_string(),
            reason: error.to_string(),
        }),
    }
}

fn unsupported(mount: &MountInfo) -> ProbeError {
    ProbeError::Unsupported {
        filesystem: mount.filesystem.clone(),
        mount_point: mount.mount_point.display().to_string(),
        reason: "only positively validated ext4 and lustre user quotas are supported",
    }
}

fn incomplete(mount: &MountInfo, reason: impl Into<String>) -> ProbeError {
    ProbeError::Incomplete {
        filesystem: mount.filesystem.clone(),
        mount_point: mount.mount_point.display().to_string(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MountInfo, ProbeError, QueryResult, classify_error, incomplete, normalize, parse_mountinfo,
    };
    use crate::quota::model::QuotaGraceState;
    use std::path::{Path, PathBuf};

    #[test]
    fn quota_mount_parser_prefers_deepest_scope_and_decodes_paths() {
        let input = "36 25 8:1 / / rw - ext4 /dev/root rw\n40 36 7:1 / /home/me/My\\040Data rw - ext4 /dev/loop0 rw";
        let mount = parse_mountinfo(input, Path::new("/home/me/My Data/project")).unwrap();
        assert_eq!(mount.mount_point, Path::new("/home/me/My Data"));
        assert_eq!(mount.source, Path::new("/dev/loop0"));
        assert_eq!(mount.mount_id, 40);
        assert_eq!((mount.device_major, mount.device_minor), (7, 1));

        let replacement = parse_mountinfo(
            "41 36 7:2 / /home/me/My\\040Data rw - ext4 /dev/loop1 rw",
            Path::new("/home/me/My Data/project"),
        )
        .unwrap();
        assert_ne!(mount, replacement);
    }

    #[test]
    fn quota_mount_parser_rejects_missing_or_invalid_identity() {
        let missing_device = "40 36 / /home rw - ext4 /dev/loop0 rw";
        let invalid_mount_id = "x 36 7:1 / /home rw - ext4 /dev/loop0 rw";
        let invalid_device = "40 36 7:x / /home rw - ext4 /dev/loop0 rw";
        for input in [missing_device, invalid_mount_id, invalid_device] {
            assert!(parse_mountinfo(input, Path::new("/home/project")).is_none());
        }
    }

    #[test]
    fn quota_normalization_requires_grace_validity() {
        // SAFETY: dqblk is a plain C data structure and zero is valid test input.
        let mut raw = unsafe { std::mem::zeroed::<libc::dqblk>() };
        raw.dqb_valid = libc::QIF_LIMITS | libc::QIF_USAGE;

        assert_eq!(
            normalize(raw, 100).unwrap_err(),
            "kernel response omitted usage, limit, or grace fields"
        );
    }

    #[test]
    fn quotactl_subject_id_preserves_the_unsigned_high_bit() {
        assert_eq!(
            super::quotactl_subject_id(i32::MIN.unsigned_abs()),
            i32::MIN
        );
    }

    #[test]
    fn quota_normalization_preserves_kernel_limits() {
        // SAFETY: dqblk is a plain C data structure and zero is valid initialization.
        let mut raw = unsafe { std::mem::zeroed::<libc::dqblk>() };
        raw.dqb_valid = libc::QIF_LIMITS | libc::QIF_USAGE | libc::QIF_TIMES;
        raw.dqb_curspace = 10;
        raw.dqb_bhardlimit = 20;
        raw.dqb_curinodes = 3;
        raw.dqb_ihardlimit = 5;
        raw.dqb_btime = 200;
        raw.dqb_itime = 100;
        let QueryResult { space, inodes } = normalize(raw, 100).unwrap();
        assert_eq!(space.hard_limit, Some(20 * 1024));
        assert_eq!(space.headroom_to_hard_limit, Some(20 * 1024 - 10));
        assert_eq!(inodes.headroom_to_hard_limit, Some(2));
        assert_eq!(space.grace.unwrap().state, QuotaGraceState::Active);
        assert_eq!(inodes.grace.unwrap().state, QuotaGraceState::Expired);
    }

    #[test]
    fn quota_provider_errors_map_to_explicit_failure_states() {
        let mount = MountInfo {
            mount_point: PathBuf::from("/home"),
            filesystem: "ext4".to_owned(),
            source: PathBuf::from("/dev/root"),
            mount_id: 36,
            device_major: 8,
            device_minor: 1,
        };

        let not_configured = classify_error(&mount, std::io::Error::from_raw_os_error(libc::ESRCH));
        let permission = classify_error(&mount, std::io::Error::from_raw_os_error(libc::EACCES));
        let unavailable = classify_error(&mount, std::io::Error::from_raw_os_error(libc::ENOSYS));
        let missing_source =
            classify_error(&mount, std::io::Error::from_raw_os_error(libc::ENOENT));

        assert!(matches!(
            not_configured,
            Err(ProbeError::NotConfigured { .. })
        ));
        assert!(matches!(
            permission,
            Err(ProbeError::PermissionDenied { .. })
        ));
        assert!(matches!(unavailable, Err(ProbeError::Unavailable { .. })));
        let Err(ProbeError::Unavailable { reason, .. }) = missing_source else {
            panic!("ENOENT must report an unavailable provider source");
        };
        assert!(!reason.is_empty());
        assert!(matches!(
            incomplete(&mount, "missing grace"),
            ProbeError::Incomplete { .. }
        ));
    }
}
