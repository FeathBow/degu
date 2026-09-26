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
