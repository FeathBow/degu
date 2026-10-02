use super::super::*;

#[test]
fn official_release_build_information_preserves_the_version() {
    for output in [
        "uv 0.12.3 (507230998 2026-08-07 aarch64-apple-darwin)\n",
        "uv 0.12.3 (507230998 2026-08-07 x86_64-unknown-linux-gnu)\n",
        "uv 0.12.3 (aarch64-apple-darwin)\n",
        "uv 0.12.3 (x86_64-unknown-linux-musl)\n",
        "uv 0.12.3 (507230998 2026-08-07)\n",
    ] {
        assert_eq!(
            parse_uv_version(output.as_bytes()),
            Ok(AUDITED_UV_PRUNE_VERSION),
            "{output:?}"
        );
    }
}

#[test]
fn build_information_cannot_hide_a_nonstable_or_ambiguous_version() {
    for output in [
        "uv 0.12.3+24 (507230998 2026-08-07 aarch64-apple-darwin)\n",
        "uv 0.12.3-alpha.1 (507230998 2026-08-07 aarch64-apple-darwin)\n",
        "uv 00.12.3 (aarch64-apple-darwin)\n",
        "uv 0.12.3.4 (aarch64-apple-darwin)\n",
        "uv 0.12.3 (aarch64-apple-darwin)\nother\n",
        "uv 0.12.3 (aarch64-apple-darwin)\r\n",
        "uv 0.12.3 (aarch64-apple-darwin)",
        "uv 0.12.3 (aarch64-apple-darwin) trailing\n",
        "uv 0.12.3 (aarch64-apple-darwin) (other)\n",
        "uv 0.12.3 ()\n",
        "uv 0.12.3 (unstructured)\n",
        "uv 0.12.3 (507230998 invalid-date aarch64-apple-darwin)\n",
        "uv 0.12.3 (not-a-hash 2026-08-07 aarch64-apple-darwin)\n",
        "uv 0.12.3 (507230998 2026-08-07 aarch64-apple-darwin extra)\n",
        "uv 0.12.3 (507230998 2026-08-07 aarch64--darwin)\n",
        "uv 0.12.3 (aarch64-apple-darwin\u{1b})\n",
    ] {
        assert!(parse_uv_version(output.as_bytes()).is_err(), "{output:?}");
    }
}

#[test]
fn exact_stable_versions_parse_and_minimum_is_inclusive() {
    assert_eq!(parse_uv_version(b"uv 0.8.19\n"), Ok(MINIMUM_UV_VERSION));
    assert_eq!(
        parse_uv_version(b"uv 12.34.56\n"),
        Ok(UvVersion::new(12, 34, 56))
    );
}

#[test]
fn ambiguous_or_nonstable_version_output_fails_closed() {
    for invalid in [
        &b"0.8.19\n"[..],
        b"uv 0.8.19",
        b"uv 0.8.19\r\n",
        b"uv 0.8.19 extra\n",
        b"uv 0.8.19-alpha.1\n",
        b"uv 0.8.19+local\n",
        b"uv 00.8.19\n",
        b"uv 0.8\n",
        b"uv 0.8.19\nother\n",
        b"uv 18446744073709551616.0.0\n",
        b"\xff\n",
    ] {
        assert!(parse_uv_version(invalid).is_err(), "accepted {invalid:?}");
    }
}
