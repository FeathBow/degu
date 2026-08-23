use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use degu_core::authority::TransactionState;
use degu_core::backend::{
    HeldTreePolicyAssessmentOutcome, assess_held_tree_policy_metadata, certify_held_fd,
};
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use degu_core::oplog::{ObjectIdentity, OpOutcome};
use degu_core::seal::wal::{ProductionAssociation, StagingLocator, TransactionId};
use degu_core::staging::{
    ForwardFailureDisposition, ForwardStagingRequest, ReadyStagingEngine,
    VerifiedPurgeFailureDisposition, VerifiedPurgeRequest, forward_filesystem_id,
};
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Mode, OFlags};

use super::super::identity;
use super::super::journal::{OperationLog, TrashRecord, trash_record};
use super::super::{mount, storage};
use super::execution::CleanExecution;
use super::policy::{self, PreparedPolicy, confined_relative};
use super::{CapturedCleanPlan, EntryIdentity};

const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const TRANSACTION_ID_ATTEMPTS: usize = 128;
const RESERVATION_ATTEMPTS: u64 = 10_000;
const RESERVATION_WIDTH: usize = 4;
const CREATE_RESERVATION: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(super) struct ProductionRun<'a> {
    pub(super) ctx: &'a DetectCtx,
    pub(super) log: OperationLog,
    pub(super) reclamation_id: String,
    pub(super) recheck: &'a dyn Fn(&Finding) -> Result<(), String>,
    pub(super) engine: &'a mut ReadyStagingEngine,
    pub(super) purge: bool,
}

pub(super) struct ProductionOutcome {
    pub(super) execution: CleanExecution,
    pub(super) recovery_blocked: bool,
}

/// Performs the data-only admission pass for every item after the caller has
/// activated and recovered the mutation session, but before this clean batch
/// may mutate a source, prepare a trash root, reserve a claim, allocate a
/// transaction, or append a transaction WAL frame. Store activation/recovery
/// may already have written bookkeeping. The returned assessment is deliberately
/// discarded: production execution repeats the complete policy and held-tree
/// checks to retain all race detection and authority boundaries.
pub(super) fn batch_preflight(
    ctx: &DetectCtx,
    plan: &CapturedCleanPlan,
) -> Option<Vec<CleanExecution>> {
    let first_failure =
        plan.items_with_identities()
            .enumerate()
            .find_map(|(index, (finding, identity))| {
                preflight_item(ctx, finding, identity)
                    .and_then(require_batch_assessment)
                    .err()
                    .map(|reason| (index, finding.path().to_path_buf(), reason))
            })?;

    Some(
        plan.items()
            .iter()
            .enumerate()
            .map(|(index, finding)| {
                if index == first_failure.0 {
                    CleanExecution::plain_stage_failed(
                        finding,
                        format!(
                            "sealed batch preflight rejected {}: {}",
                            finding.path().display(),
                            first_failure.2
                        ),
                    )
                } else {
                    CleanExecution::not_attempted(
                        finding,
                        format!(
                            "sealed batch preflight did not attempt {} because {} failed preflight: {}",
                            finding.path().display(),
                            first_failure.1.display(),
                            first_failure.2
                        ),
                    )
                }
            })
            .collect(),
    )
}

fn require_batch_assessment(outcome: HeldTreePolicyAssessmentOutcome) -> Result<(), String> {
    match outcome {
        HeldTreePolicyAssessmentOutcome::TreePolicyAssessed { .. } => Ok(()),
        HeldTreePolicyAssessmentOutcome::TreePolicyDeferredUntilSourceParentSeal {
            reason, ..
        } => Err(format!(
            "tree policy assessment was deferred until the source-parent seal ({reason:?}); atomic selected clean requires every tree policy to be evaluable before execution"
        )),
    }
}

fn preflight_item(
    ctx: &DetectCtx,
    finding: &Finding,
    identity: &EntryIdentity,
) -> Result<HeldTreePolicyAssessmentOutcome, String> {
    // Match ordinary production's primary-failure order exactly. In particular,
    // a pathname policy failure must not be masked by a held-tree deferral or
    // assessment error that ordinary `execute` would never reach first.
    let _policy = preflight_policy(ctx, finding, identity)?;

    let lexical_parent = finding
        .path()
        .parent()
        .ok_or_else(|| "sealed staging source has no parent".to_string())?;
    let canonical_parent = std::fs::canonicalize(lexical_parent)
        .map_err(|error| format!("failed to canonicalize sealed staging source parent: {error}"))?;
    let root_basename = finding
        .path()
        .file_name()
        .ok_or_else(|| "sealed staging source has no basename".to_string())?;
    let source_parent = open_directory(&canonical_parent)
        .map_err(|error| format!("failed to hold sealed staging source parent: {error}"))?;
    let parent_evidence = certify_held_fd(source_parent)
        .map_err(|error| format!("sealed staging source-parent certification failed: {error:?}"))?;
    assess_held_tree_policy_metadata(parent_evidence, root_basename)
        .map_err(|error| error.to_string())
}

struct HeldReservation {
    destination_parent: OwnedFd,
    destination_basename: OsString,
    claims: OwnedFd,
    claim_basename: OsString,
    claim_identity: ObjectIdentity,
}

impl HeldReservation {
    fn reserve(destination_parent: OwnedFd, source: &Path) -> io::Result<(Self, OsString)> {
        let claims = rustix::fs::openat(
            &destination_parent,
            ".claims",
            OPEN_DIRECTORY,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let source_name = source
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no basename"))?;
        let mut sequence = next_sequence(&destination_parent)?;
        for _ in 0..RESERVATION_ATTEMPTS {
            let claim_basename =
                OsString::from(format!("{sequence:0width$}", width = RESERVATION_WIDTH));
            let mut destination_basename = claim_basename.clone();
            destination_basename.push("-");
            destination_basename.push(source_name);
            match rustix::fs::statat(
                &destination_parent,
                &destination_basename,
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "trash destination already exists",
                    ));
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(io::Error::from(error)),
            }
            match rustix::fs::openat(
                &claims,
                &claim_basename,
                CREATE_RESERVATION,
                Mode::RUSR.union(Mode::WUSR),
            ) {
                Ok(claim) => {
                    let stat = rustix::fs::fstat(&claim).map_err(io::Error::from)?;
                    let claim_identity = super::super::trash::parent_identity(&stat);
                    return Ok((
                        Self {
                            destination_parent,
                            destination_basename: destination_basename.clone(),
                            claims,
                            claim_basename,
                            claim_identity,
                        },
                        destination_basename,
                    ));
                }
                Err(rustix::io::Errno::EXIST) => {
                    sequence = sequence.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "trash sequence overflow")
                    })?;
                }
                Err(error) => return Err(io::Error::from(error)),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "trash sequence claims exhausted",
        ))
    }

    fn duplicate_destination_parent(&self) -> io::Result<OwnedFd> {
        rustix::io::dup(&self.destination_parent).map_err(io::Error::from)
    }

    fn destination_present(&self) -> io::Result<bool> {
        match rustix::fs::statat(
            &self.destination_parent,
            &self.destination_basename,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(io::Error::from(error)),
        }
    }

    fn destination_identity(&self) -> io::Result<ObjectIdentity> {
        let stat = rustix::fs::statat(
            &self.destination_parent,
            &self.destination_basename,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        Ok(super::super::trash::parent_identity(&stat))
    }

    fn release(&self) -> io::Result<()> {
        let stat = rustix::fs::statat(
            &self.claims,
            &self.claim_basename,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        if super::super::trash::parent_identity(&stat) != self.claim_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trash reservation identity changed before cleanup",
            ));
        }
        super::super::trash::removal::remove_held_file(
            &self.claims,
            &self.claim_basename,
            Path::new("sealed-staging reservation"),
            self.claim_identity,
        )
    }
}

pub(super) fn execute(
    run: &mut ProductionRun<'_>,
    finding: &Finding,
    identity: &EntryIdentity,
) -> ProductionOutcome {
    let policy = match preflight_policy(run.ctx, finding, identity) {
        Ok(policy) => policy,
        Err(reason) => return failed(finding, reason, false),
    };

    // Root creation is deliberately after all static production-policy gates.
    // Reservation is later still, after the exact managed root is authenticated.
    let trash_root = match super::prepare_trash_root(run.ctx, finding.path()) {
        Ok(root) => root,
        Err(reason) => return failed(finding, reason, false),
    };
    let canonical_trash_root = match std::fs::canonicalize(&trash_root) {
        Ok(root) if root == policy.trash_root => root,
        Ok(root) => {
            return failed(
                finding,
                format!(
                    "sealed staging trash root changed during preparation: {} != {}",
                    root.display(),
                    policy.trash_root.display()
                ),
                false,
            );
        }
        Err(error) => {
            return failed(
                finding,
                format!("failed to canonicalize sealed staging trash root: {error}"),
                false,
            );
        }
    };
    let destination_parent = match open_directory(&canonical_trash_root) {
        Ok(parent) => parent,
        Err(error) => {
            return failed(
                finding,
                format!("failed to hold sealed staging destination parent: {error}"),
                false,
            );
        }
    };
    let (held, destination_basename) =
        match HeldReservation::reserve(destination_parent, &policy.canonical_source) {
            Ok(reservation) => reservation,
            Err(error) => return failed(finding, error.to_string(), false),
        };
    let entry = canonical_trash_root.join(destination_basename);

    let result = execute_reserved(run, finding, identity, &policy, &held, entry.clone());
    match result {
        Ok(execution) => ProductionOutcome {
            execution,
            recovery_blocked: false,
        },
        Err((reason, disposition)) => {
            let blocked = disposition == ForwardFailureDisposition::RecoveryBlocked;
            let quarantined =
                disposition == ForwardFailureDisposition::Terminal(TransactionState::Quarantined);
            // Never remove a claim while recovery is blocked or quarantined.
            // Report a destination only when no-follow inspection proves that
            // exact namespace entry exists; WAL/claim evidence may be retained
            // even when the prospective destination was never published.
            let entry_for_report = match held.destination_present() {
                Ok(true) => Some(entry.clone()),
                Ok(false) => None,
                Err(error) => {
                    return classified_failure(
                        finding,
                        None,
                        format!(
                            "{reason}; sealed staging could not inspect the held prospective destination, so WAL and reservation evidence were retained: {error}"
                        ),
                        ForwardFailureDisposition::RecoveryBlocked,
                    );
                }
            };
            // Release the reservation marker for every non-recoverable failure,
            // whether or not a prospective destination exists; only blocked or
            // quarantined states retain the claim as recovery evidence.
            if !blocked
                && !quarantined
                && let Err(error) = held.release()
            {
                return failed(
                    finding,
                    format!("{reason}; trash reservation cleanup failed: {error}"),
                    false,
                );
            }
            classified_failure(finding, entry_for_report, reason, disposition)
        }
    }
}

fn execute_reserved(
    run: &mut ProductionRun<'_>,
    finding: &Finding,
    identity: &EntryIdentity,
    policy: &PreparedPolicy,
    held: &HeldReservation,
    entry: PathBuf,
) -> Result<CleanExecution, (String, ForwardFailureDisposition)> {
    match identity.matches(&policy.canonical_source) {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                "clean item identity changed before sealed staging".into(),
                ForwardFailureDisposition::NotStarted,
            ));
        }
        Err(error) => {
            return Err((
                format!("clean item identity recheck failed before sealed staging: {error}"),
                ForwardFailureDisposition::NotStarted,
            ));
        }
    }

    let source_parent = policy.canonical_source.parent().ok_or_else(|| {
        (
            "sealed staging source has no canonical parent".into(),
            ForwardFailureDisposition::NotStarted,
        )
    })?;
    let destination_parent = entry.parent().ok_or_else(|| {
        (
            "sealed staging destination has no canonical parent".into(),
            ForwardFailureDisposition::NotStarted,
        )
    })?;
    let source_parent_relative = confined_relative(&policy.recovery_anchor, source_parent)
        .map_err(|reason| (reason, ForwardFailureDisposition::NotStarted))?;
    let destination_parent_relative =
        confined_relative(&policy.recovery_anchor, destination_parent)
            .map_err(|reason| (reason, ForwardFailureDisposition::NotStarted))?;
    let source_basename = policy
        .canonical_source
        .file_name()
        .ok_or_else(|| {
            (
                "sealed staging source has no basename".into(),
                ForwardFailureDisposition::NotStarted,
            )
        })?
        .to_os_string();
    let destination_basename = entry
        .file_name()
        .ok_or_else(|| {
            (
                "sealed staging destination has no basename".into(),
                ForwardFailureDisposition::NotStarted,
            )
        })?
        .to_os_string();

    let (source_anchor, destination_anchor) = mount::open_pair_fds(&policy.recovery_anchor)
        .map_err(|error| {
            (
                format!("failed to authenticate mount-domain anchors: {error}"),
                ForwardFailureDisposition::NotStarted,
            )
        })?;
    let source_parent_fd = open_directory(source_parent).map_err(|error| {
        (
            format!("failed to hold sealed staging source parent: {error}"),
            ForwardFailureDisposition::NotStarted,
        )
    })?;
    let destination_parent_fd = held.duplicate_destination_parent().map_err(|error| {
        (
            format!("failed to duplicate the held sealed staging destination parent: {error}"),
            ForwardFailureDisposition::NotStarted,
        )
    })?;
    let filesystem_id = forward_filesystem_id(&source_anchor).map_err(|error| {
        (
            format!("failed to derive sealed staging filesystem identity: {error}"),
            ForwardFailureDisposition::NotStarted,
        )
    })?;
    let source_locator = StagingLocator::new(source_parent_relative, filesystem_id.clone())
        .ok_or_else(|| {
            (
                "invalid mount-domain source locator".into(),
                ForwardFailureDisposition::NotStarted,
            )
        })?;
    let destination_locator = StagingLocator::new(destination_parent_relative, filesystem_id)
        .ok_or_else(|| {
            (
                "invalid mount-domain destination locator".into(),
                ForwardFailureDisposition::NotStarted,
            )
        })?;
    let restore_parent = identity::capture_parent_following(source_parent).map_err(|error| {
        (
            format!("failed to capture restore parent before sealed staging: {error}"),
            ForwardFailureDisposition::NotStarted,
        )
    })?;
    let association = ProductionAssociation::new(run.reclamation_id.clone()).ok_or_else(|| {
        (
            "invalid sealed staging reclamation association".into(),
            ForwardFailureDisposition::NotStarted,
        )
    })?;
    let request = ForwardStagingRequest::new(
        source_anchor,
        source_parent_fd,
        source_locator,
        source_basename,
        destination_anchor,
        destination_parent_fd,
        destination_locator,
        destination_basename,
    )
    .with_production_association(association)
    .with_recovery_anchor(policy.recovery_anchor.clone());
    let transaction = random_unused_transaction(run.engine)
        .map_err(|error| (error.to_string(), ForwardFailureDisposition::NotStarted))?;

    // Repeat the existing full protection and disablement checks only after
    // every adapter-side request input is fixed, immediately before the core
    // coordinator's preflight and first WAL frame.
    (run.recheck)(finding).map_err(|reason| {
        (
            format!("protection re-check failed at the sealed staging boundary: {reason}"),
            ForwardFailureDisposition::NotStarted,
        )
    })?;

    match run.engine.stage_to_verified_commit(transaction, request) {
        Ok(commit) => debug_assert_eq!(commit.transaction(), transaction),
        // An ambiguous rename error that recovery certified as VerifiedCommitted
        // is a durable success: the object is staged and WAL-owned. Reporting it
        // as a stage failure would undercount freed space, skip the oplog record,
        // and leave undo blocked by the WAL guard with no restore path.
        Err(error)
            if error.disposition()
                == ForwardFailureDisposition::Terminal(TransactionState::VerifiedCommitted) => {}
        Err(error) => {
            return Err((
                format!(
                    "sealed staging transaction {} failed during {}: {error}",
                    transaction_hex(error.transaction()),
                    error.stage()
                ),
                error.disposition(),
            ));
        }
    }

    // The object is already durably VerifiedCommitted. Neither reopening the mount anchor nor
    // the purge admission below may be reported as a stage failure: that would skip
    // the oplog record, undercount freed space, and wedge undo. Only a poisoned WAL
    // escalates to recovery-blocked; every other purge failure degrades to "staged
    // in trash, not deleted" and still writes the durable oplog record.
    let mut purge_admission_failure: Option<String> = None;
    let purge_request = if run.purge {
        match mount::open_pair_fds(&policy.recovery_anchor) {
            Ok((source_anchor, destination_anchor)) => Some(VerifiedPurgeRequest::new(
                transaction,
                run.reclamation_id.clone(),
                source_anchor,
                destination_anchor,
            )),
            Err(error) => {
                purge_admission_failure = Some(format!(
                    "failed to retain purge mount-domain anchors after VerifiedCommitted: {error}"
                ));
                None
            }
        }
    } else {
        None
    };

    let current_identity = held.destination_identity().map_err(|error| {
        (
            format!("VerifiedCommitted destination identity projection failed: {error}"),
            ForwardFailureDisposition::RecoveryBlocked,
        )
    })?;
    let reservation_cleanup_failure = held.release().err().map(|error| error.to_string());
    let record = trash_record(TrashRecord {
        finding,
        trash_entry: Some(entry.clone()),
        reclamation_id: Some(run.reclamation_id.clone()),
        expected_identity: Some(current_identity),
        destination_parent: Some(restore_parent),
        outcome: OpOutcome::Ok,
    });
    let jsonl_projection_failure = run.log.append(&record).err().map(|error| error.to_string());
    let purged = if let Some(request) = purge_request {
        match run.engine.request_verified_purge(request) {
            Ok(authority) => {
                // No fallible adapter step is permitted between minting and
                // consuming the one-use held authority on this exact ready engine
                // generation.
                let commit = run
                    .engine
                    .execute_verified_purge(authority)
                    .map_err(|error| {
                        (
                            format!(
                                "explicit sealed purge execution failed during {}: {error}",
                                error.stage()
                            ),
                            ForwardFailureDisposition::RecoveryBlocked,
                        )
                    })?;
                debug_assert_eq!(commit.transaction(), transaction);
                true
            }
            // A poisoned WAL must stop the session; the object stays committed.
            Err(error)
                if matches!(
                    error.disposition(),
                    VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired)
                        | VerifiedPurgeFailureDisposition::RecoveryBlocked
                ) =>
            {
                return Err((
                    format!(
                        "explicit sealed purge admission failed during {}: {error}",
                        error.stage()
                    ),
                    ForwardFailureDisposition::RecoveryBlocked,
                ));
            }
            // The object stays durably staged in trash; a non-recovery admission
            // failure is not a stage failure and must not skip the oplog record.
            Err(error) => {
                purge_admission_failure = Some(format!(
                    "purge admission failed during {}: {error}",
                    error.stage()
                ));
                false
            }
        }
    } else {
        false
    };

    if purged {
        let failures = [
            reservation_cleanup_failure.map(|error| format!("reservation cleanup failed: {error}")),
            jsonl_projection_failure
                .map(|error| format!("operation-log projection failed: {error}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        Ok(CleanExecution::production_purged(
            finding,
            entry,
            (!failures.is_empty()).then(|| failures.join("; ")),
        ))
    } else if let Some(admission) = purge_admission_failure {
        let mut reason = format!(
            "object is durably staged in trash but sealed purge failed, so it was not deleted and can be restored with `degu undo`: {admission}"
        );
        if let Some(error) = reservation_cleanup_failure {
            reason.push_str(&format!("; reservation cleanup failed: {error}"));
        }
        if let Some(error) = jsonl_projection_failure {
            reason.push_str(&format!("; operation-log projection failed: {error}"));
        }
        Ok(CleanExecution::production_purge_admission_failed(
            finding, entry, reason,
        ))
    } else {
        Ok(CleanExecution::production_staged(
            finding,
            entry,
            reservation_cleanup_failure,
            jsonl_projection_failure,
        ))
    }
}

fn classified_failure(
    finding: &Finding,
    entry: Option<PathBuf>,
    reason: String,
    disposition: ForwardFailureDisposition,
) -> ProductionOutcome {
    match disposition {
        ForwardFailureDisposition::Terminal(TransactionState::Quarantined) => ProductionOutcome {
            execution: CleanExecution::quarantined(finding, entry, reason),
            // Quarantine retains active sealed-staging authority. Do not admit
            // another batch item only to discover that at admission.
            recovery_blocked: true,
        },
        ForwardFailureDisposition::RecoveryBlocked => ProductionOutcome {
            execution: CleanExecution::recovery_blocked(finding, entry, reason),
            recovery_blocked: true,
        },
        ForwardFailureDisposition::NotStarted | ForwardFailureDisposition::Terminal(_) => {
            failed(finding, reason, false)
        }
    }
}

fn preflight_policy(
    ctx: &DetectCtx,
    finding: &Finding,
    identity: &EntryIdentity,
) -> Result<PreparedPolicy, String> {
    let source = policy::assess_source(finding, identity)?;
    let lexical_trash = storage::resolve_existing_trash_dir(ctx, source.canonical_source())?;
    policy::complete(source, lexical_trash)
}

fn next_sequence(destination_parent: &OwnedFd) -> io::Result<u64> {
    let duplicate = rustix::io::dup(destination_parent).map_err(io::Error::from)?;
    let mut maximum = 0_u64;
    for entry in rustix::fs::Dir::read_from(duplicate).map_err(io::Error::from)? {
        let entry = entry.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        let prefix = bytes.split(|byte| *byte == b'-').next().unwrap_or(bytes);
        if !prefix.is_empty()
            && prefix.iter().all(u8::is_ascii_digit)
            && let Ok(value) = std::str::from_utf8(prefix)
            && let Ok(sequence) = value.parse::<u64>()
        {
            maximum = maximum.max(sequence);
        }
    }
    maximum
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "trash sequence overflow"))
}

fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    rustix::fs::open(path, OPEN_DIRECTORY, Mode::empty()).map_err(io::Error::from)
}

fn transaction_hex(transaction: TransactionId) -> String {
    let mut encoded = String::with_capacity(transaction.0.len() * 2);
    for byte in transaction.0 {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn random_unused_transaction(engine: &ReadyStagingEngine) -> io::Result<TransactionId> {
    unused_transaction_with(
        |bytes| getrandom::fill(bytes).map_err(io::Error::other),
        |transaction| engine.state(transaction).is_some(),
    )
}

fn unused_transaction_with(
    mut fill: impl FnMut(&mut [u8; 16]) -> io::Result<()>,
    mut exists: impl FnMut(TransactionId) -> bool,
) -> io::Result<TransactionId> {
    for _ in 0..TRANSACTION_ID_ATTEMPTS {
        let mut bytes = [0u8; 16];
        fill(&mut bytes)?;
        let transaction = TransactionId(bytes);
        if !exists(transaction) {
            return Ok(transaction);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "128-bit transaction id collisions exhausted",
    ))
}

fn failed(finding: &Finding, reason: String, recovery_blocked: bool) -> ProductionOutcome {
    ProductionOutcome {
        execution: CleanExecution::plain_stage_failed(finding, reason),
        recovery_blocked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn deferred_tree_assessment_is_always_rejected_by_atomic_preflight() {
        use degu_core::backend::{
            HeldTreePolicyDeferralReason, SourceParentSealAssessment,
            SourceParentSealAssessmentStatus,
        };

        let deferred =
            || HeldTreePolicyAssessmentOutcome::TreePolicyDeferredUntilSourceParentSeal {
                reason: HeldTreePolicyDeferralReason::SourceParentSearchRequiresExecutionSeal,
                source_parent_seal: SourceParentSealAssessment {
                    original_mode: 0o400,
                    projected_mode: 0o700,
                    validation: SourceParentSealAssessmentStatus::RequiresExecutionValidation,
                },
            };

        let rejection = require_batch_assessment(deferred()).unwrap_err();
        assert!(rejection.contains("atomic selected clean"), "{rejection}");
        assert!(
            rejection.contains("SourceParentSearchRequiresExecutionSeal"),
            "{rejection}"
        );
    }

    #[test]
    fn real_0400_parent_preserves_ordinary_path_policy_as_primary_failure() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping 0400 policy-order fixture while running as root");
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join("state");
        let parent = home.path().join("source-parent");
        let source = parent.join("root");
        std::fs::create_dir(&state).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("payload"), b"data").unwrap();
        for path in [
            home.path(),
            state.as_path(),
            parent.as_path(),
            source.as_path(),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let state = state.canonicalize().unwrap();
        let ctx = DetectCtx::for_test(
            home.path().canonicalize().unwrap(),
            [("XDG_STATE_HOME", state.as_os_str())],
        );
        let finding = super::super::tests::finding_for_test(source.clone(), 1, 1);
        let identity = EntryIdentity::capture(&source).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o400)).unwrap();

        // The preview/core companion test proves this same 0400 shape can
        // produce a held-tree deferral when assessment is tried first. Atomic
        // production must nevertheless preserve ordinary pathname policy.
        let ordinary = preflight_policy(&ctx, &finding, &identity).unwrap_err();
        let atomic = preflight_item(&ctx, &finding, &identity).unwrap_err();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(atomic, ordinary);
        assert!(
            atomic.contains("failed to inspect sealed staging source")
                || atomic.contains("failed to canonicalize sealed staging source"),
            "{atomic}"
        );
        assert!(!atomic.contains("deferred"), "{atomic}");
        assert!(!state.join("degu/trash").exists());
        assert!(!state.join("degu/sealed-staging").exists());
    }

    #[test]
    fn quarantined_and_recovery_blocked_outcomes_stop_the_batch_and_keep_the_entry() {
        let finding = super::super::tests::finding_for_test(PathBuf::from("/cache"), 1, 1);
        let entry = PathBuf::from("/trash/0001-cache");
        for (disposition, state) in [
            (
                ForwardFailureDisposition::Terminal(TransactionState::Quarantined),
                "quarantined",
            ),
            (
                ForwardFailureDisposition::RecoveryBlocked,
                "recovery_blocked",
            ),
        ] {
            let outcome = classified_failure(
                &finding,
                Some(entry.clone()),
                "injected production fault".into(),
                disposition,
            );
            assert!(outcome.recovery_blocked, "batch did not stop for {state}");
            assert_eq!(outcome.execution.state_label(), state);
            assert_eq!(outcome.execution.trash_entry(), Some(entry.as_path()));
            assert!(outcome.execution.requires_manual_recovery());
        }
    }

    #[test]
    fn occupied_prior_destination_is_preserved_and_next_sequence_is_used() {
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join("state");
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = state.canonicalize().unwrap();
        let source = home.path().canonicalize().unwrap().join("cache");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("source"), b"source").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ctx = DetectCtx::for_test(
            home.path().canonicalize().unwrap(),
            [("XDG_STATE_HOME", state.as_os_str())],
        );
        let trash_root = ctx.xdg_state().join("degu/trash");
        std::fs::create_dir_all(trash_root.join("0001-cache")).unwrap();
        std::fs::write(trash_root.join("0001-cache/occupant"), b"keep").unwrap();
        for path in [ctx.xdg_state().join("degu"), trash_root.clone()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let finding = super::super::tests::finding_for_test(source.clone(), 4096, 2);
        let identity = EntryIdentity::capture(&source).unwrap();
        let store = degu_core::seal::store::SealWalStore::open_or_create_for_integration_test(
            &ctx.xdg_state().join("degu/sealed-staging"),
        )
        .unwrap();
        let (engine, startup) =
            degu_core::staging::SealedStagingEngine::open_for_integration_test(&store).unwrap();
        let (mut ready, _) = engine
            .recover_startup(startup, |_, _| {
                Err(io::Error::other("empty recovery must not request anchors"))
            })
            .unwrap();
        let mut run = ProductionRun {
            ctx: &ctx,
            log: OperationLog::new(&ctx),
            reclamation_id: "conflict-test".to_string(),
            recheck: &|_| Ok(()),
            engine: &mut ready,
            purge: false,
        };

        let outcome = execute(&mut run, &finding, &identity);
        assert!(
            !outcome.execution.failed(),
            "{:?}",
            outcome.execution.failure_reason()
        );
        assert_eq!(outcome.execution.state_label(), "staged");
        assert!(!source.exists());
        assert_eq!(
            outcome.execution.trash_entry(),
            Some(trash_root.join("0002-cache").as_path())
        );
        assert_eq!(
            std::fs::metadata(source.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read(trash_root.join("0001-cache/occupant")).unwrap(),
            b"keep"
        );
        assert!(!trash_root.join(".claims/0002").exists());
        let entries = run.engine.production_entries();
        assert_eq!(entries.len(), 1);
        let recovery_anchor = entries[0]
            .recovery_anchor()
            .expect("production staging must persist its recovery anchor");
        source
            .parent()
            .unwrap()
            .strip_prefix(recovery_anchor)
            .expect("recovery anchor must confine the source parent");
    }

    #[test]
    fn held_reservation_cleanup_cannot_be_redirected_by_trash_root_replacement() {
        let home = tempfile::tempdir().unwrap();
        let trash = home.path().join("trash");
        std::fs::create_dir_all(trash.join(".claims")).unwrap();
        for path in [
            home.path(),
            trash.as_path(),
            trash.join(".claims").as_path(),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let source = home.path().join("cache");
        let parent = open_directory(&trash).unwrap();
        let (held, destination) = HeldReservation::reserve(parent, &source).unwrap();
        assert_eq!(destination, OsString::from("0001-cache"));

        let detached = home.path().join("detached-trash");
        std::fs::rename(&trash, &detached).unwrap();
        std::fs::create_dir_all(trash.join(".claims")).unwrap();
        for path in [trash.as_path(), trash.join(".claims").as_path()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(trash.join(".claims/0001"), b"").unwrap();

        held.release().unwrap();
        assert!(!detached.join(".claims/0001").exists());
        assert!(trash.join(".claims/0001").is_file());
    }

    #[test]
    fn transaction_hex_is_fixed_width_and_adapter_local() {
        assert_eq!(
            transaction_hex(TransactionId([
                0x00, 0x01, 0x0f, 0x10, 0x2a, 0x7f, 0x80, 0xff, 0x55, 0xaa, 0x03, 0x30, 0x99, 0x09,
                0xd0, 0x0d,
            ])),
            "00010f102a7f80ff55aa03309909d00d"
        );
    }

    #[test]
    fn rng_collisions_retry_until_an_unused_transaction_is_found() {
        let mut fills = 0_u8;
        let transaction = unused_transaction_with(
            |bytes| {
                fills = fills.saturating_add(1);
                *bytes = [fills; 16];
                Ok(())
            },
            |candidate| candidate == TransactionId([1; 16]),
        )
        .unwrap();

        assert_eq!(transaction, TransactionId([2; 16]));
        assert_eq!(fills, 2);
    }

    #[test]
    fn rng_collision_budget_fails_before_transaction_admission() {
        let calls = std::cell::Cell::new(0_usize);
        let error = unused_transaction_with(
            |bytes| {
                calls.set(calls.get() + 1);
                *bytes = [0xa3; 16];
                Ok(())
            },
            |_| true,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(calls.get(), TRANSACTION_ID_ATTEMPTS);
        assert!(error.to_string().contains("collisions exhausted"));
    }

    #[test]
    fn rng_failure_is_not_misreported_as_a_collision() {
        let error = unused_transaction_with(
            |_| Err(io::Error::other("production entropy source failed")),
            |_| false,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("entropy source failed"));
    }
}
