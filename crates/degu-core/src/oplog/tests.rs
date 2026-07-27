use super::*;

fn identity_for_test() -> ObjectIdentity {
    ObjectIdentity {
        kind: ObjectKind::Directory,
        device: 1,
        inode: 2,
        ctime_seconds: 3,
        ctime_nanoseconds: 4,
    }
}

#[test]
fn moved_pending_accepts_only_the_same_stable_object() {
    let expected = identity_for_test();
    let moved = ObjectIdentity {
        ctime_nanoseconds: 5,
        ..expected
    };
    let replaced = ObjectIdentity { inode: 6, ..moved };
    let cases = [
        (moved, PendingState::Moved),
        (replaced, PendingState::AmbiguousIdentity),
    ];

    for (destination, state) in cases {
        assert_eq!(
            reconcile_pending_move(
                PendingProbe::Missing,
                PendingProbe::Present(destination),
                Some(expected),
            ),
            state
        );
    }
}

#[test]
fn pending_layout_and_source_identity_are_fail_closed() {
    let expected = identity_for_test();
    let changed_source = ObjectIdentity {
        ctime_nanoseconds: 7,
        ..expected
    };
    let cases = [
        (
            PendingProbe::Present(expected),
            PendingProbe::Missing,
            Some(expected),
            PendingState::NotMoved,
        ),
        (
            PendingProbe::Present(changed_source),
            PendingProbe::Missing,
            Some(expected),
            PendingState::AmbiguousIdentity,
        ),
        (
            PendingProbe::Present(expected),
            PendingProbe::Present(expected),
            None,
            PendingState::AmbiguousBothExist,
        ),
        (
            PendingProbe::Missing,
            PendingProbe::Missing,
            None,
            PendingState::AmbiguousBothMissing,
        ),
        (
            PendingProbe::Failed,
            PendingProbe::Missing,
            Some(expected),
            PendingState::AmbiguousIdentity,
        ),
    ];

    for (source, destination, identity, state) in cases {
        assert_eq!(reconcile_pending_move(source, destination, identity), state);
    }
}
