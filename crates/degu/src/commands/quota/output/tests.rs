use super::{format_count, render_dimension, render_human};
use crate::quota::model::{
    ActiveQuota, QuotaDimension, QuotaGrace, QuotaGraceState, QuotaLimits, QuotaScope,
    QuotaScopeIdentity, QuotaSnapshot, SubjectQuota,
};
use crate::runtime::{Glyphs, Ui};
use std::path::PathBuf;

#[test]
fn quota_human_escapes_scope_and_provider_terminal_controls() {
    let scope = QuotaScope::new(
        PathBuf::from("/tmp/target\nrow"),
        PathBuf::from("/mnt/\tdata"),
        "ext4\x1b[31m".to_owned(),
        QuotaScopeIdentity::new(36, 8, 1, PathBuf::from("/dev/root")),
    );
    let report = QuotaSnapshot::active(
        scope,
        1000,
        ActiveQuota {
            provider: "linux_vfs\x1b]8;;unsafe\x07",
            data_source: "linux_quotactl\x1b[2J",
            space: QuotaDimension::new(10, QuotaLimits::new(20, 30), None),
            inodes: QuotaDimension::new(1, QuotaLimits::new(2, 3), None),
        },
    );

    let rendered = render_human(&report, Ui::test_terminal(120));

    assert!(!rendered.contains('\x1b'));
    assert!(rendered.contains("/tmp/target\\nrow"));
    assert!(rendered.contains("/mnt/\\tdata"));
    assert!(rendered.contains("ext4\\u{1b}[31m"));
    assert!(rendered.contains("linux_vfs\\u{1b}]8;;unsafe\\u{7}"));
    assert!(rendered.contains("linux_quotactl\\u{1b}[2J"));
    assert!(!rendered.contains("Status"));
}

#[test]
fn quota_human_reflows_fields_for_a_narrow_terminal() {
    use unicode_width::UnicodeWidthStr;

    let scope = QuotaScope::new(
        PathBuf::from("/home/user/a-very-long-quota-target"),
        PathBuf::from("/home/user/a-very-long-mount-point"),
        "ext4".to_owned(),
        QuotaScopeIdentity::new(36, 8, 1, PathBuf::from("/dev/root")),
    );
    let report = QuotaSnapshot::active(
        scope,
        1000,
        ActiveQuota {
            provider: "linux_vfs",
            data_source: "linux_quotactl",
            space: QuotaDimension::new(10, QuotaLimits::new(20, 30), None),
            inodes: QuotaDimension::new(1, QuotaLimits::new(2, 3), None),
        },
    );

    let rendered = render_human(&report, Ui::test_terminal(32));

    assert!(
        rendered
            .lines()
            .all(|line| UnicodeWidthStr::width(line) <= 32),
        "{rendered}"
    );
    let compact = rendered.split_whitespace().collect::<String>();
    assert!(compact.contains("/home/user/a-very-long-quota-target"));
    assert!(compact.contains("/home/user/a-very-long-mount-point"));
}

#[test]
fn quota_human_dimension_shows_pressure_and_remaining_allowance() {
    let dimension = QuotaDimension::new(10, QuotaLimits::new(15, 20), None);
    let rendered = render_dimension(
        "Inodes",
        &dimension,
        |value| value.to_string(),
        Glyphs::UNICODE,
    );
    assert!(rendered.contains("50.0% of hard limit █████░░░░░"));
    assert!(rendered.contains("10 used"));
    assert!(rendered.contains("soft 15"));
    assert!(rendered.contains("hard 20"));
    assert!(rendered.contains("5 remaining to soft limit"));
    assert!(rendered.contains("10 remaining to hard limit"));
}

#[test]
fn quota_pressure_bar_caps_fill_but_not_the_reported_percentage() {
    let dimension = QuotaDimension::new(25, QuotaLimits::new(15, 20), None);
    let rendered = render_dimension(
        "Inodes",
        &dimension,
        |value| value.to_string(),
        Glyphs::UNICODE,
    );
    assert!(rendered.contains("125.0% of hard limit ██████████"));
    assert!(rendered.contains("soft limit exceeded by 10"));
    assert!(rendered.contains("hard limit exceeded by 5"));
}

#[test]
fn quota_pressure_uses_the_soft_limit_when_no_hard_limit_exists() {
    let dimension = QuotaDimension::new(10, QuotaLimits::new(20, 0), None);
    let rendered = render_dimension(
        "Inodes",
        &dimension,
        |value| value.to_string(),
        Glyphs::UNICODE,
    );
    assert!(rendered.contains("50.0% of soft limit █████░░░░░"));
    assert!(rendered.contains("10 remaining to soft limit"));
}

#[test]
fn quota_boundaries_distinguish_at_limit_from_exceeded() {
    let at_soft = QuotaDimension::new(10, QuotaLimits::new(10, 20), None);
    let exceeded = QuotaDimension::new(25, QuotaLimits::new(10, 20), None);

    let at_soft = render_dimension(
        "Inodes",
        &at_soft,
        |value| value.to_string(),
        Glyphs::UNICODE,
    );
    let exceeded = render_dimension(
        "Inodes",
        &exceeded,
        |value| value.to_string(),
        Glyphs::UNICODE,
    );

    assert!(at_soft.contains("at soft limit"));
    assert!(at_soft.contains("10 remaining to hard limit"));
    assert!(exceeded.contains("soft limit exceeded by 15"));
    assert!(exceeded.contains("hard limit exceeded by 5"));
}

#[test]
fn quota_without_limits_reports_usage_without_inventing_pressure() {
    let dimension = QuotaDimension::new(10, QuotaLimits::new(0, 0), None);
    let rendered = render_dimension(
        "Inodes",
        &dimension,
        |value| value.to_string(),
        Glyphs::UNICODE,
    );
    assert!(rendered.contains("no configured limit"));
    assert!(rendered.contains("10 used · soft unlimited · hard unlimited"));
    assert!(!rendered.contains('%'));
}

#[test]
fn quota_human_grace_reports_active_and_expired_states_with_utc_deadlines() {
    const DEADLINE: u64 = 1_700_000_000;
    let active = QuotaDimension::new(
        10,
        QuotaLimits::new(5, 20),
        QuotaGrace::from_kernel_deadline(DEADLINE, DEADLINE - 1),
    );
    let expired = QuotaDimension::new(
        10,
        QuotaLimits::new(5, 20),
        QuotaGrace::from_kernel_deadline(DEADLINE, DEADLINE),
    );
    let below_soft = QuotaDimension::new(
        4,
        QuotaLimits::new(5, 20),
        QuotaGrace::from_kernel_deadline(DEADLINE, DEADLINE - 1),
    );

    let active = render_dimension("Inodes", &active, format_count, Glyphs::UNICODE);
    let expired = render_dimension("Inodes", &expired, format_count, Glyphs::UNICODE);
    let below_soft = render_dimension("Inodes", &below_soft, format_count, Glyphs::UNICODE);

    assert!(active.contains("grace active until 2023-11-14T22:13:20Z"));
    assert!(expired.contains("grace expired at 2023-11-14T22:13:20Z"));
    assert!(!below_soft.contains("grace "));
    let soft = active.find("soft limit exceeded").unwrap();
    let grace = active.find("grace active").unwrap();
    let hard = active.find("remaining to hard limit").unwrap();
    assert!(soft < grace && grace < hard, "{active}");
}

#[test]
fn quota_human_expired_grace_without_deadline_never_invents_a_timestamp() {
    let grace = QuotaGrace {
        state: QuotaGraceState::Expired,
        expires_at_unix: None,
    };
    let dimension = QuotaDimension::new(10, QuotaLimits::new(5, 20), Some(grace));

    let rendered = render_dimension("Space", &dimension, format_count, Glyphs::UNICODE);

    assert!(
        rendered.contains("grace period has expired (provider reports no deadline)"),
        "{rendered}"
    );
    assert!(!rendered.contains("Unix"), "{rendered}");
}

fn lustre_user() -> QuotaSnapshot {
    QuotaSnapshot::active(
        QuotaScope::new(
            PathBuf::from("/scratch/me"),
            PathBuf::from("/scratch"),
            "lustre".to_owned(),
            QuotaScopeIdentity::new(36, 0, 1, PathBuf::from("server:/scratch")),
        ),
        1000,
        ActiveQuota {
            provider: "lustre_lfs",
            data_source: "lfs_quota",
            space: QuotaDimension::new(8, QuotaLimits::new(0, 0), None),
            inodes: QuotaDimension::new(8, QuotaLimits::new(0, 0), None),
        },
    )
}

// The whole point: a user with no limit of their own must not read as unlimited
// when the project they write into is nearly out of inodes.
#[test]
fn quota_human_leads_with_the_closest_limit() {
    let report = lustre_user().with_subjects(vec![
        SubjectQuota::active(
            "project",
            654_321,
            QuotaDimension::new(2_307_527_940, QuotaLimits::new(0, 5_368_709_120), None),
            QuotaDimension::new(828_409, QuotaLimits::new(0, 1_024_000), None),
        ),
        SubjectQuota::active(
            "group",
            2000,
            QuotaDimension::new(9, QuotaLimits::new(0, 0), None),
            QuotaDimension::new(9, QuotaLimits::new(0, 0), None),
        ),
    ]);

    let rendered = render_human(&report, Ui::test_terminal(120));

    let closest = rendered.find("Closest").unwrap();
    let first_section = rendered.find("User 1000").unwrap();
    assert!(closest < first_section, "{rendered}");
    let line = rendered
        .lines()
        .find(|line| line.starts_with("Closest"))
        .unwrap();
    assert!(
        line.contains("project 654321 inodes 80.9% of hard limit"),
        "{line}"
    );
    assert!(line.contains("195591 remaining to hard limit"), "{line}");
    assert!(rendered.contains("Project 654321"), "{rendered}");
    assert!(rendered.contains("Group 2000"), "{rendered}");
}

#[test]
fn quota_human_says_nothing_is_configured() {
    let rendered = render_human(&lustre_user(), Ui::test_terminal(120));
    assert!(rendered.contains("no limit configured"), "{rendered}");
    // A single subject needs no section title.
    assert!(!rendered.contains("User 1000"), "{rendered}");
}

// With a subject unread, "no limit found" must not read as "no limit".
#[test]
fn quota_human_refuses_to_claim_unlimited() {
    let report = lustre_user().with_subjects(vec![SubjectQuota::unavailable(
        "group",
        Some(2000),
        "Connection refused\x1b[2J".to_owned(),
    )]);

    let rendered = render_human(&report, Ui::test_terminal(120));

    assert!(!rendered.contains("no limit configured"), "{rendered}");
    assert!(rendered.contains("unknown: no limit found"), "{rendered}");
    assert!(rendered.contains("Group 2000"), "{rendered}");
    assert!(
        rendered.contains("could not be read: Connection refused"),
        "{rendered}"
    );
    assert!(!rendered.contains('\x1b'), "{rendered:?}");
}

#[test]
fn quota_human_doubts_a_partial_answer() {
    let report = QuotaSnapshot::active(
        QuotaScope::new(
            PathBuf::from("/home/me"),
            PathBuf::from("/home"),
            "nfs4".to_owned(),
            QuotaScopeIdentity::new(36, 0, 1, PathBuf::from("server:/home")),
        ),
        1000,
        ActiveQuota {
            provider: "nfs_rquota",
            data_source: "quota_tool",
            space: QuotaDimension::new(10, QuotaLimits::new(0, 100), None),
            inodes: QuotaDimension::new(1, QuotaLimits::new(0, 100), None),
        },
    )
    .with_subjects(vec![SubjectQuota::unavailable(
        "group",
        Some(2000),
        "Connection refused".to_owned(),
    )]);

    let rendered = render_human(&report, Ui::test_terminal(120));

    assert!(
        rendered.contains("user 1000 space 10.0% of hard limit"),
        "{rendered}"
    );
    assert!(rendered.contains("may not be the real one"), "{rendered}");
}
