//! Fixed activation-anchor layouts and account-base lookup.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The XDG state suffix a self-managed anchor lives under, relative to the
/// account home. It is a fixed convention, never read from `$XDG_STATE_HOME`,
/// so ambient environment drift cannot select a different anchor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const SELF_STATE_COMPONENTS: &[&str] = &[".local", "state"];

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MIN_PASSWD_BUFFER_BYTES: usize = 1024;

/// Errors resolving the current effective user's account base.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccountBaseError {
    /// `getpwuid_r` failed with this errno.
    #[error("account lookup failed with errno {0}")]
    Lookup(i32),
    /// No consulted account source names the effective UID.
    #[error("no account source has an entry for the effective UID")]
    AccountMissing,
    /// The host's account resolver exists but could not be consulted: it
    /// exceeded its time or output bound, or could not be run. Distinct from
    /// [`AccountBaseError::AccountMissing`], which is a settled answer.
    #[error("the host's account resolver could not be consulted")]
    ResolverUnavailable,
    /// The account home is empty or not absolute, so joining it would depend on
    /// the working directory.
    #[error("the account home is empty or not absolute")]
    HomeNotAbsolute,
}

/// The operating-system prefix. Provisioning treats it as existing-only and
/// never creates or repairs it.
#[cfg(target_os = "linux")]
pub(super) const OS_PREFIX_COMPONENTS: &[&str] = &["var", "lib"];
#[cfg(target_os = "macos")]
pub(super) const OS_PREFIX_COMPONENTS: &[&str] = &["private", "var", "db"];

/// The degu-owned scaffold published beneath the OS prefix. `[0]` is the product
/// namespace, `[1]` the per-UID leaf's parent.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const PRODUCT_COMPONENTS: &[&str] = &["degu", "store-activation"];

/// Absolute parent of the per-UID system activation anchors.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn system_anchor_root() -> PathBuf {
    let mut path = PathBuf::from("/");
    for component in OS_PREFIX_COMPONENTS {
        path.push(component);
    }
    for component in PRODUCT_COMPONENTS {
        path.push(component);
    }
    path
}

/// Existing account-owned base beneath which the self-managed scaffold is
/// created. This is an account fact, never an environment-selected path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn self_anchor_base() -> Result<PathBuf, AccountBaseError> {
    let uid = rustix::process::geteuid().as_raw();
    let home = passwd_home_dir(uid)?.ok_or(AccountBaseError::AccountMissing)?;
    if !home.is_absolute() {
        return Err(AccountBaseError::HomeNotAbsolute);
    }
    Ok(home)
}

/// Fixed self-managed activation-anchor path for the current effective UID.
///
/// Runtime selection and provisioning deliberately share this account-database
/// derivation. Ambient HOME, XDG, cwd, configuration, and CLI input cannot
/// redirect either side of the protocol.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn current_self_anchor_path() -> Result<PathBuf, AccountBaseError> {
    let uid = rustix::process::geteuid().as_raw();
    self_anchor_path_for_uid(uid)?.ok_or(AccountBaseError::AccountMissing)
}

/// Fixed self-managed candidate for `uid`, when the account database contains
/// that UID. Administrator setup uses this only to refuse a competing system
/// initialization; it never creates or selects the path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn self_anchor_path_for_uid(
    uid: libc::uid_t,
) -> Result<Option<PathBuf>, AccountBaseError> {
    let Some(mut path) = passwd_home_dir(uid)? else {
        return Ok(None);
    };
    if !path.is_absolute() {
        return Err(AccountBaseError::HomeNotAbsolute);
    }
    for component in SELF_STATE_COMPONENTS {
        path.push(component);
    }
    for component in PRODUCT_COMPONENTS {
        path.push(component);
    }
    path.push(uid.to_string());
    Ok(Some(path))
}

/// Home directory of `uid` from the account database, never from `$HOME`, so the
/// result is a stable account fact rather than ambient state.
///
/// `getpwuid_r` answers whenever this build can see the host's configured name
/// services. A statically linked build cannot: the switch resolves its backends
/// by loading plugins, which a static image has no way to load, so an account
/// held in LDAP, SSSD, or winbind reads as absent. That is not "no such user",
/// and the two are indistinguishable at the libc call — musl reports a missing
/// entry with a success status and a null result, never an errno. So a miss
/// falls through to [`delegated_home_dir`], which puts the same question to the
/// host's own resolver in a separate process.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn passwd_home_dir(uid: libc::uid_t) -> Result<Option<PathBuf>, AccountBaseError> {
    if let Some(home) = libc_home_dir(uid).map_err(AccountBaseError::Lookup)? {
        return Ok(Some(home));
    }
    #[cfg(target_os = "linux")]
    {
        delegated_home_dir(uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(None)
    }
}

/// Home directory of `uid` as this build's libc reports it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn libc_home_dir(uid: libc::uid_t) -> Result<Option<PathBuf>, i32> {
    // SAFETY: querying the recommended reentrant passwd buffer size takes no pointers.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer = vec![
        0_u8;
        usize::try_from(suggested)
            .unwrap_or(MIN_PASSWD_BUFFER_BYTES)
            .max(MIN_PASSWD_BUFFER_BYTES)
    ];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: entry, result, and buffer stay valid for the call; getpwuid_r
        // initializes entry on success.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            let capacity = buffer.len().checked_mul(2).ok_or(libc::ENOMEM)?;
            buffer.resize(capacity, 0);
            continue;
        }
        if status != 0 {
            return Err(status);
        }
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: successful getpwuid_r initialized entry.
        let entry = unsafe { entry.assume_init() };
        if entry.pw_dir.is_null() {
            return Err(libc::EINVAL);
        }
        // SAFETY: pw_dir points into the still-alive buffer and is a C string.
        let dir = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
        let bytes = dir.to_bytes();
        if bytes.is_empty() {
            return Ok(Some(PathBuf::new()));
        }
        return Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes))));
    }
}

/// Absolute paths the host's account resolver may live at, in preference order.
/// Never resolved through `PATH`: the tool is trusted because of where it is.
#[cfg(target_os = "linux")]
const RESOLVER_BINARIES: &[&str] = &["/usr/bin/getent", "/bin/getent"];

/// Bound on the resolver. A cached SSSD or winbind answer costs single-digit
/// milliseconds; anything approaching this means the directory service is
/// wedged, and degu refuses rather than hangs.
#[cfg(target_os = "linux")]
const RESOLVER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One passwd record is a few hundred bytes. This admits a generous record and
/// refuses a flood.
#[cfg(target_os = "linux")]
const RESOLVER_OUTPUT_CAP_BYTES: usize = 8 * 1024;

/// Home directory of `uid` according to the host's own account resolver.
///
/// This is not a weaker source than `getpwuid_r` and not a guess: `getent`
/// consults exactly the name services the host is configured to use, which is
/// what a dynamically linked build would have consulted in-process. The answer
/// therefore carries the same authority, and admits no path the account
/// database does not already name — ambient environment still cannot redirect
/// the protocol.
///
/// Absence is itself an answer. A host with no resolver at these paths has no
/// name service switch either, so its libc lookup was already complete and a
/// miss really does mean the account does not exist.
#[cfg(target_os = "linux")]
fn delegated_home_dir(uid: libc::uid_t) -> Result<Option<PathBuf>, AccountBaseError> {
    delegated_home_dir_from(RESOLVER_BINARIES, uid)
}

/// [`delegated_home_dir`] against an explicit resolver list, so tests can stand
/// a resolver in for the host's.
#[cfg(target_os = "linux")]
fn delegated_home_dir_from(
    binaries: &[&str],
    uid: libc::uid_t,
) -> Result<Option<PathBuf>, AccountBaseError> {
    let uid_argument = uid.to_string();
    let arguments = [
        std::ffi::OsStr::new("passwd"),
        std::ffi::OsStr::new(&uid_argument),
    ];
    for binary in binaries {
        let run = crate::system_tool::run_capped(
            std::path::Path::new(binary),
            &arguments,
            RESOLVER_TIMEOUT,
            RESOLVER_OUTPUT_CAP_BYTES,
        );
        match run {
            // The resolver answered. Its verdict stands either way; a second
            // path would only be the same tool reached by another name.
            Ok(run) if run.success => return Ok(parse_passwd_record(&run.stdout, uid)),
            Ok(_) => return Ok(None),
            // Nothing at this path; the next one may be the same tool under
            // another name.
            Err(crate::system_tool::ToolError::NotInstalled(_)) => continue,
            // The resolver exists but could not answer. That is not a settled
            // "no such account", and must not be reported as one.
            Err(_) => return Err(AccountBaseError::ResolverUnavailable),
        }
    }
    Ok(None)
}

/// Home directory from one passwd record, admitted only when the record is
/// unambiguous and answers the question that was asked.
///
/// The UID column is the authentication: it proves the resolver returned the
/// account degu named, not whatever it happened to have. Splitting on bytes
/// keeps home directories that are not valid UTF-8.
#[cfg(target_os = "linux")]
fn parse_passwd_record(output: &[u8], uid: libc::uid_t) -> Option<PathBuf> {
    let record = output.strip_suffix(b"\n").unwrap_or(output);
    // More than one record for a single UID is ambiguous, never a reason to
    // pick one.
    if record.is_empty() || record.contains(&b'\n') {
        return None;
    }
    let fields: Vec<&[u8]> = record.split(|byte| *byte == b':').collect();
    if fields.len() != 7 {
        return None;
    }
    if std::str::from_utf8(fields[2])
        .ok()?
        .parse::<libc::uid_t>()
        .ok()?
        != uid
    {
        return None;
    }
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(fields[5]));
    home.is_absolute().then_some(home)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A directory-service UID, well outside the local-file range.
    const UID: libc::uid_t = 2000001;

    fn record(line: &str) -> Option<PathBuf> {
        parse_passwd_record(line.as_bytes(), UID)
    }

    #[test]
    fn a_directory_service_record_yields_its_home() {
        assert_eq!(
            record(
                "svc.example:*:2000001:2000001:Service Example:/home/g01/svc.example:/bin/bash\n"
            ),
            Some(PathBuf::from("/home/g01/svc.example"))
        );
    }

    #[test]
    fn a_record_without_the_trailing_newline_is_accepted() {
        assert_eq!(
            record("u:*:2000001:1:gecos:/home/u:/bin/sh"),
            Some(PathBuf::from("/home/u"))
        );
    }

    #[test]
    fn a_record_for_another_uid_is_refused() {
        assert_eq!(record("root:*:0:0:root:/root:/bin/bash\n"), None);
    }

    #[test]
    fn two_records_are_ambiguous_rather_than_a_choice() {
        assert_eq!(
            record(concat!(
                "a:*:2000001:1:x:/home/a:/bin/sh\n",
                "b:*:2000001:1:x:/home/b:/bin/sh\n"
            )),
            None
        );
    }

    #[test]
    fn a_relative_or_empty_home_is_refused() {
        assert_eq!(record("u:*:2000001:1:x:home/u:/bin/sh\n"), None);
        assert_eq!(record("u:*:2000001:1:x::/bin/sh\n"), None);
    }

    #[test]
    fn a_record_with_the_wrong_column_count_is_refused() {
        assert_eq!(record("u:*:2000001:1:x:/home/u\n"), None);
        assert_eq!(record("u:*:2000001:1:x:/home/u:/bin/sh:extra\n"), None);
    }

    #[test]
    fn empty_output_is_not_a_record() {
        assert_eq!(record(""), None);
        assert_eq!(record("\n"), None);
    }

    #[test]
    fn a_home_that_is_not_utf8_survives() {
        let output = b"u:*:2000001:1:x:/home/\xff\xfe:/bin/sh\n";
        let home = parse_passwd_record(output, UID).expect("a non-UTF-8 home is still a path");
        assert_eq!(
            home,
            PathBuf::from(std::ffi::OsStr::from_bytes(b"/home/\xff\xfe"))
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod delegate_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    const UID: libc::uid_t = 2000001;

    /// A stand-in resolver whose whole behaviour is the script body it is given.
    struct FakeResolver {
        _directory: tempfile::TempDir,
        path: String,
    }

    fn resolver(body: &str) -> FakeResolver {
        let directory = crate::secure_test_tempdir().expect("a private temp directory");
        let path = directory.path().join("getent");
        let mut file = std::fs::File::create(&path).expect("the resolver is writable");
        write!(file, "#!/bin/sh\n{body}\n").expect("the resolver body is written");
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("the resolver is executable");
        wait_until_runnable(&path);
        FakeResolver {
            path: path.to_str().expect("a UTF-8 temp path").to_owned(),
            _directory: directory,
        }
    }

    /// A script this process just wrote races every other test in the binary:
    /// until each of their forked children reaches its own exec, that child
    /// holds a duplicate of our write descriptor and the kernel refuses to run
    /// the file. Drain that window here, so it cannot surface as a resolver
    /// that could not be consulted and be mistaken for the behaviour under
    /// test. Production writes no executables and cannot reach this.
    fn wait_until_runnable(path: &std::path::Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match std::process::Command::new(path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
            {
                Ok(_) => return,
                Err(error) if std::time::Instant::now() >= deadline => {
                    panic!("the stand-in resolver never became runnable: {error}")
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
    }

    #[test]
    fn a_resolver_record_supplies_the_home() {
        let fake =
            resolver("printf 'svc.example:*:2000001:2000001:x:/home/g01/svc.example:/bin/sh\\n'");
        assert_eq!(
            delegated_home_dir_from(&[&fake.path], UID),
            Ok(Some(PathBuf::from("/home/g01/svc.example")))
        );
    }

    #[test]
    fn the_arguments_the_resolver_receives_name_the_uid() {
        let fake = resolver("printf 'svc:*:2000001:1:x:/home/%s/%s:/bin/sh\\n' \"$1\" \"$2\"");
        assert_eq!(
            delegated_home_dir_from(&[&fake.path], UID),
            Ok(Some(PathBuf::from("/home/passwd/2000001")))
        );
    }

    #[test]
    fn a_resolver_that_reports_no_such_key_yields_nothing() {
        // getent's own convention: exit 2, print nothing.
        let fake = resolver("exit 2");
        assert_eq!(delegated_home_dir_from(&[&fake.path], UID), Ok(None));
    }

    #[test]
    fn a_record_for_a_different_uid_is_not_an_answer() {
        let fake = resolver("printf 'root:*:0:0:root:/root:/bin/sh\\n'");
        assert_eq!(delegated_home_dir_from(&[&fake.path], UID), Ok(None));
    }

    #[test]
    fn a_missing_first_path_falls_through_to_the_next() {
        let fake = resolver("printf 'svc:*:2000001:1:x:/home/svc:/bin/sh\\n'");
        assert_eq!(
            delegated_home_dir_from(&["/nonexistent/getent", &fake.path], UID),
            Ok(Some(PathBuf::from("/home/svc")))
        );
    }

    #[test]
    fn no_resolver_at_all_is_a_complete_answer() {
        assert_eq!(
            delegated_home_dir_from(&["/nonexistent/getent"], UID),
            Ok(None)
        );
    }

    /// Output past the bound is a resolver that cannot be trusted to have
    /// answered, not a resolver reporting that the account is absent.
    #[test]
    fn a_flooding_resolver_is_unavailable_rather_than_a_settled_miss() {
        let fake = resolver(
            "printf 'svc:*:2000001:1:x:/home/svc:/bin/sh\\n'; head -c 20000 /dev/zero | tr '\\0' 'x'",
        );
        assert_eq!(
            delegated_home_dir_from(&[&fake.path], UID),
            Err(AccountBaseError::ResolverUnavailable)
        );
    }
}
