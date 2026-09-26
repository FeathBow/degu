use super::*;

/// A directory-service UID, well outside the local-file range.
const UID: libc::uid_t = 2000001;

fn record(line: &str) -> Option<PathBuf> {
    parse_passwd_record(line.as_bytes(), UID)
}

#[test]
fn a_directory_service_record_yields_its_home() {
    assert_eq!(
        record("svc.example:*:2000001:2000001:Service Example:/home/g01/svc.example:/bin/bash\n"),
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
