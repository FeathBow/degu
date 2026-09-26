use super::*;

/// An advisory is asked for only where degu has no answer. A location it
/// withheld because it recognized a user asset is already decided, and
/// sending it would widen what leaves the machine to no purpose.
#[test]
fn only_what_degu_could_not_classify_is_sent() {
    let findings = [
        unknown_recovery("/home/account/.cache/mystery"),
        unknown_ownership("/home/account/.cache/shared"),
        user_asset("/home/account/Documents"),
        eligible("/home/account/.cache/pip"),
    ];
    let asked: Vec<String> = subjects(&findings, &home())
        .into_iter()
        .map(|subject| subject.path)
        .collect();
    let sent = |path: &str| asked.iter().any(|asked| asked == path);
    assert!(sent("~/.cache/mystery"), "{asked:?}");
    assert!(sent("~/.cache/shared"), "{asked:?}");
    assert!(!sent("~/Documents"), "a settled user asset was sent");
    assert!(!sent("~/.cache/pip"), "a classified cache was sent");
}

/// A cache outside the account home has no prefix degu can remove: on the
/// machines degu targets the ordinary case is `/scratch/<user>/...`, where
/// the account name is a path component. Only the last component goes, and
/// the subject admits the rest was dropped.
#[test]
fn a_location_outside_the_home_travels_without_its_ancestors() {
    let findings = [unknown_recovery("/scratch/someuser/weirdcache")];
    let subjects = subjects(&findings, &home());
    assert_eq!(subjects.len(), 1);
    assert_eq!(subjects[0].path, "weirdcache");
    assert!(subjects[0].ancestors_withheld);
    let payload = serde_json::to_string(&Request {
        degu_advisory_request: 1,
        subjects: &subjects,
    })
    .expect("a request encodes");
    assert!(!payload.contains("someuser"), "{payload}");
    assert!(!payload.contains("/scratch"), "{payload}");
}

/// Under the home the elided path is already anonymous, so the shape is
/// kept whole and nothing is claimed to be withheld.
#[test]
fn a_location_under_the_home_keeps_its_shape() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let subjects = subjects(&findings, &home());
    assert_eq!(subjects[0].path, "~/.cache/mystery");
    assert!(!subjects[0].ancestors_withheld);
}

/// The account home never leaves the machine: a signature carries the shape
/// of a location, not whose it is.
#[test]
fn a_subject_carries_an_elided_path() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let payload = serde_json::to_string(&Request {
        degu_advisory_request: 1,
        subjects: &subjects(&findings, &home()),
    })
    .expect("a request encodes");
    assert!(!payload.contains("/home/account"), "{payload}");
    assert!(payload.contains("~/.cache/mystery"), "{payload}");
}

#[test]
fn an_answer_is_attached_to_the_location_it_was_asked_about() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let subjects = subjects(&findings, &home());
    let advisories = Advisor {
        command: "/bin/advisor",
        shown: "~/bin/advisor",
        timeout: Duration::from_secs(1),
    }
    .consult(&subjects, answer("ok"));
    let advice = advisories
        .for_path(Path::new("/home/account/.cache/mystery"))
        .expect("advice for the subject");
    assert_eq!(advice.summary, "a build cache");
    assert_eq!(advice.check.as_deref(), Some("tool cache dir"));
    assert_eq!(advisories.unavailable(), None);
}

/// The ordinary case on the machines degu targets is a cache outside the
/// home, whose subject carries only its last component. The answer still has
/// to reach the location it was asked about.
#[test]
fn an_answer_reaches_a_location_outside_the_home() {
    let findings = [unknown_recovery("/scratch/someuser/weirdcache")];
    let subjects = subjects(&findings, &home());
    let advisories = Advisor {
        command: "/bin/advisor",
        shown: "~/bin/advisor",
        timeout: Duration::from_secs(1),
    }
    .consult(&subjects, answer("ok"));
    assert!(
        advisories
            .for_path(Path::new("/scratch/someuser/weirdcache"))
            .is_some(),
        "advice for a location outside the home was dropped"
    );
}

/// An advisor answers by the id it was given. Anything else it names is a
/// location degu did not ask about, and attaching a sentence there would let
/// a foreign program speak about a path it was never shown.
#[test]
fn an_answer_about_an_id_that_was_not_asked_is_dropped() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let subjects = subjects(&findings, &home());
    let advisories = Advisor {
        command: "/bin/advisor",
        shown: "~/bin/advisor",
        timeout: Duration::from_secs(1),
    }
    .consult(&subjects, answer("wrong-id"));
    assert!(
        advisories
            .for_path(Path::new("/home/account/.cache/mystery"))
            .is_none()
    );
}

#[test]
fn an_empty_summary_is_not_an_advisory() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let subjects = subjects(&findings, &home());
    let advisories = Advisor {
        command: "/bin/advisor",
        shown: "~/bin/advisor",
        timeout: Duration::from_secs(1),
    }
    .consult(&subjects, answer("empty-summary"));
    assert!(
        advisories
            .for_path(Path::new("/home/account/.cache/mystery"))
            .is_none()
    );
}

/// Advisory text is a foreign program's bytes on their way to a terminal.
#[test]
fn advisory_text_cannot_carry_terminal_control() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let subjects = subjects(&findings, &home());
    let advisories = Advisor {
        command: "/bin/advisor",
        shown: "~/bin/advisor",
        timeout: Duration::from_secs(1),
    }
    .consult(&subjects, answer("escapes"));
    let advice = advisories
        .for_path(Path::new("/home/account/.cache/mystery"))
        .expect("advice");
    assert!(!advice.summary.contains('\u{1b}'), "{}", advice.summary);
}

#[test]
fn a_long_answer_is_bounded() {
    let long = "x".repeat(MAX_SUMMARY_CHARS * 3);
    let bounded = bounded(&long, MAX_SUMMARY_CHARS);
    assert_eq!(bounded.chars().count(), MAX_SUMMARY_CHARS + 1);
    assert!(bounded.ends_with('…'));
}

/// Every way an advisor can fail is an absence of advice, never an error the
/// reader has to clear: the review has to open either way.
#[test]
fn a_failing_advisor_is_an_absence_not_an_error() {
    let findings = [unknown_recovery("/home/account/.cache/mystery")];
    let subjects = subjects(&findings, &home());
    for canned in ["fails", "garbage"] {
        let advisories = Advisor {
            command: "/bin/advisor",
            shown: "~/bin/advisor",
            timeout: Duration::from_secs(1),
        }
        .consult(&subjects, answer(canned));
        assert!(
            matches!(advisories.unavailable(), Some(Unavailable::Failed(_))),
            "{canned} did not report a failure"
        );
        assert!(
            advisories
                .for_path(Path::new("/home/account/.cache/mystery"))
                .is_none()
        );
    }
}

#[test]
fn a_request_is_bounded_in_subjects() {
    let paths: Vec<String> = (0..MAX_SUBJECTS + 10)
        .map(|index| format!("/home/account/.cache/m{index}"))
        .collect();
    let findings: Vec<Finding> = paths.iter().map(|path| unknown_recovery(path)).collect();
    assert_eq!(subjects(&findings, &home()).len(), MAX_SUBJECTS);
}
