//! Deterministic system/self selection, durable peer witnessing, and explicit self initialization.

use super::*;

/// Internal fixed locator. Public callers can neither construct one nor
/// activate an individual authority outside the system/self selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationAuthorityMode {
    AdministratorHardened,
    SelfManaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnchorKind {
    System,
    SelfManaged,
    #[cfg(test)]
    Test,
    #[cfg(feature = "integration-test-anchor")]
    IntegrationTest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ActivationAnchorLocator {
    pub(super) path: PathBuf,
    pub(super) kind: AnchorKind,
}

impl ActivationAnchorLocator {
    pub(super) fn for_current_euid() -> Result<Self, StoreActivationError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let path = crate::provision::system_anchor_root()
                .join(rustix::process::geteuid().as_raw().to_string());
            Ok(Self {
                path,
                kind: AnchorKind::System,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(StoreActivationError::Backend(
                CertificationError::UnsupportedPlatform,
            ))
        }
    }

    pub(super) fn for_current_euid_self() -> Result<Self, StoreActivationError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            Ok(Self {
                path: crate::provision::current_self_anchor_path()
                    .map_err(StoreActivationError::AccountBase)?,
                kind: AnchorKind::SelfManaged,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(StoreActivationError::Backend(
                CertificationError::UnsupportedPlatform,
            ))
        }
    }

    pub(super) fn as_path(&self) -> &Path {
        &self.path
    }

    #[cfg(any(test, feature = "integration-test-anchor"))]
    pub(super) fn mode(&self) -> ActivationAuthorityMode {
        match self.kind {
            AnchorKind::System => ActivationAuthorityMode::AdministratorHardened,
            AnchorKind::SelfManaged => ActivationAuthorityMode::SelfManaged,
            #[cfg(test)]
            AnchorKind::Test => ActivationAuthorityMode::AdministratorHardened,
            #[cfg(feature = "integration-test-anchor")]
            AnchorKind::IntegrationTest => ActivationAuthorityMode::AdministratorHardened,
        }
    }
}

/// Authenticated result of the deterministic current-account authority selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentEuidAuthorityReadiness {
    mode: ActivationAuthorityMode,
    path: PathBuf,
    backend: CertifiedLocalBackend,
    activation: StoreActivationKind,
}

impl CurrentEuidAuthorityReadiness {
    pub fn mode(&self) -> ActivationAuthorityMode {
        self.mode
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn backend(&self) -> CertifiedLocalBackend {
        self.backend
    }

    pub fn activation(&self) -> StoreActivationKind {
        self.activation
    }
}

pub(super) struct AuthorityCandidate {
    pub(super) authority: AuthorityRoot,
    pub(super) state: StoreActivationState,
    pub(super) claim: Option<AuthorityRecord>,
}

pub(super) struct AuthoritySelection {
    pub(super) mode: ActivationAuthorityMode,
    pub(super) selected: AuthorityCandidate,
    pub(super) peer: Option<AuthorityCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthorityChoice {
    System,
    SelfManaged,
}

fn state_has_activation_evidence(kind: StoreActivationKind) -> bool {
    !matches!(kind, StoreActivationKind::NeverActivated)
}

pub(super) fn choose_authority(
    system: Option<StoreActivationKind>,
    self_managed: Option<StoreActivationKind>,
) -> Result<AuthorityChoice, ()> {
    match (system, self_managed) {
        (Some(_), None) => Ok(AuthorityChoice::System),
        (None, Some(_)) => Ok(AuthorityChoice::SelfManaged),
        (Some(system), Some(self_managed)) => {
            let system_has_evidence = state_has_activation_evidence(system);
            let self_has_evidence = state_has_activation_evidence(self_managed);
            match (system_has_evidence, self_has_evidence) {
                (true, true) => Err(()),
                (false, true) => Ok(AuthorityChoice::SelfManaged),
                (true, false) | (false, false) => Ok(AuthorityChoice::System),
            }
        }
        (None, None) => unreachable!("missing authorities are classified with their fixed paths"),
    }
}

pub(super) fn open_authority_candidate(
    locator: &ActivationAnchorLocator,
) -> Result<Option<AuthorityCandidate>, StoreActivationError> {
    let authority = match open_activation_anchor(locator) {
        Ok(authority) => authority,
        Err(StoreActivationError::AnchorNotProvisioned { .. }) => return Ok(None),
        Err(error) => return Err(error),
    };
    let claim = read_optional_authority(&authority).map_err(store_error_from_record_read)?;
    let state = discover_with_authority(&authority)?;
    Ok(Some(AuthorityCandidate {
        authority,
        state,
        claim,
    }))
}

fn claim_matches_candidate_activation(
    candidate: &AuthorityCandidate,
    claim: &AuthorityRecord,
) -> Result<bool, StoreActivationError> {
    let prepare =
        read_optional_prepare(&candidate.authority).map_err(store_error_from_record_read)?;
    Ok(prepare
        .as_ref()
        .is_none_or(|prepare| prepare.activation_id == claim.selection_id))
}

fn claimed_authority_choice(
    system: &Option<AuthorityCandidate>,
    self_managed: &Option<AuthorityCandidate>,
    system_path: &Path,
    self_path: &Path,
) -> Result<Option<AuthorityChoice>, StoreActivationError> {
    let system_claim = system
        .as_ref()
        .and_then(|candidate| candidate.claim.as_ref());
    let self_claim = self_managed
        .as_ref()
        .and_then(|candidate| candidate.claim.as_ref());
    let claim = match (system_claim, self_claim) {
        (None, None) => return Ok(None),
        (Some(system), Some(self_managed)) if system != self_managed => {
            return Err(StoreActivationError::SplitAuthority {
                system: system_path.to_path_buf(),
                self_managed: self_path.to_path_buf(),
            });
        }
        (Some(claim), _) | (_, Some(claim)) => claim,
    };

    let (choice, selected, peer) = if claim.selected_locator == system_path {
        (AuthorityChoice::System, system, self_managed)
    } else if claim.selected_locator == self_path {
        (AuthorityChoice::SelfManaged, self_managed, system)
    } else {
        let witness = system_claim
            .map(|_| system_path)
            .or_else(|| self_claim.map(|_| self_path))
            .unwrap_or(system_path);
        return Err(StoreActivationError::AuthorityClaimInvalid {
            path: witness.to_path_buf(),
        });
    };
    let Some(selected) = selected.as_ref() else {
        let witness = system_claim
            .map(|_| system_path)
            .or_else(|| self_claim.map(|_| self_path))
            .unwrap_or(system_path);
        return Err(StoreActivationError::SelectedAuthorityLost {
            selected: claim.selected_locator.clone(),
            witness: witness.to_path_buf(),
        });
    };
    if selected.authority.identity != claim.selected_identity
        || selected.authority.backend != claim.selected_backend
        || !claim_matches_candidate_activation(selected, claim)?
    {
        return Err(StoreActivationError::AuthorityClaimInvalid {
            path: selected.authority.path.clone(),
        });
    }
    if let Some(peer) = peer.as_ref()
        && state_has_activation_evidence(peer.state.kind())
    {
        return Err(StoreActivationError::SplitAuthority {
            system: system_path.to_path_buf(),
            self_managed: self_path.to_path_buf(),
        });
    }
    Ok(Some(choice))
}

pub(super) fn select_authority_pair(
    system_locator: ActivationAnchorLocator,
    self_locator: ActivationAnchorLocator,
) -> Result<AuthoritySelection, StoreActivationError> {
    // Every selector acquires the system anchor first and the self anchor
    // second. Holding both locks through the mutation session prevents two
    // selector users from publishing competing activation evidence.
    let system = open_authority_candidate(&system_locator)?;
    let self_managed = open_authority_candidate(&self_locator)?;
    if system.is_none() && self_managed.is_none() {
        return Err(StoreActivationError::NoAuthority {
            system: system_locator.path,
            self_managed: self_locator.path,
        });
    }
    let inherited_claim = system
        .as_ref()
        .and_then(|candidate| candidate.claim.clone())
        .or_else(|| {
            self_managed
                .as_ref()
                .and_then(|candidate| candidate.claim.clone())
        });
    let choice = match claimed_authority_choice(
        &system,
        &self_managed,
        &system_locator.path,
        &self_locator.path,
    )? {
        Some(choice) => choice,
        None => choose_authority(
            system.as_ref().map(|candidate| candidate.state.kind()),
            self_managed
                .as_ref()
                .map(|candidate| candidate.state.kind()),
        )
        .map_err(|()| StoreActivationError::SplitAuthority {
            system: system_locator.path.clone(),
            self_managed: self_locator.path.clone(),
        })?,
    };

    match choice {
        AuthorityChoice::System => {
            let mut selected = system.expect("choice requires a system authority");
            if selected.claim.is_none() {
                selected.claim = inherited_claim;
            }
            Ok(AuthoritySelection {
                mode: ActivationAuthorityMode::AdministratorHardened,
                selected,
                peer: self_managed,
            })
        }
        AuthorityChoice::SelfManaged => {
            let mut selected = self_managed.expect("choice requires a self-managed authority");
            if selected.claim.is_none() {
                selected.claim = inherited_claim;
            }
            Ok(AuthoritySelection {
                mode: ActivationAuthorityMode::SelfManaged,
                selected,
                peer: system,
            })
        }
    }
}

pub(super) fn select_current_euid_authority() -> Result<AuthoritySelection, StoreActivationError> {
    select_authority_pair(
        ActivationAnchorLocator::for_current_euid()?,
        ActivationAnchorLocator::for_current_euid_self()?,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAuthorityInitializationOutcome {
    pub provisioning: crate::provision::ActivationAnchorProvisioningOutcome,
    pub declared: bool,
}

impl SelfAuthorityInitializationOutcome {
    pub fn mutated(&self) -> bool {
        self.provisioning.mutated() || self.declared
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SelfAuthorityInitializationError {
    #[error(transparent)]
    Provision(#[from] crate::provision::ActivationAnchorProvisioningError),
    #[error(transparent)]
    Authority(#[from] StoreActivationError),
}

pub(super) fn require_current_self_path_with<F>(
    expected: &Path,
    lookup: F,
) -> Result<(), StoreActivationError>
where
    F: FnOnce() -> Result<PathBuf, crate::provision::AccountBaseError>,
{
    let actual = lookup().map_err(StoreActivationError::AccountBase)?;
    if actual != expected {
        return Err(StoreActivationError::AccountBaseChanged {
            expected: expected.to_path_buf(),
            actual,
        });
    }
    Ok(())
}

fn require_current_self_path(expected: &Path) -> Result<(), StoreActivationError> {
    require_current_self_path_with(expected, crate::provision::current_self_anchor_path)
}

/// Provision and durably declare the current non-root account's self-managed
/// authority. `initial` is the caller's assertion that no earlier authority was
/// lost; it is never repair, migration, or recovery permission.
pub fn initialize_current_euid_self_authority(
    initial: bool,
) -> Result<SelfAuthorityInitializationOutcome, SelfAuthorityInitializationError> {
    if !initial {
        return Err(StoreActivationError::InitialAssertionRequired.into());
    }
    let system_locator = ActivationAnchorLocator::for_current_euid()?;
    if let Some(system) = open_authority_candidate(&system_locator)? {
        return Err(StoreActivationError::SystemAuthorityPresent {
            path: system.authority.path,
        }
        .into());
    }

    let outcome = crate::provision::provision_current_euid_self_activation_anchor()?;
    let expected_self_path = outcome.path.clone();
    require_current_self_path(&expected_self_path)?;
    let self_locator = ActivationAnchorLocator {
        path: expected_self_path.clone(),
        kind: AnchorKind::SelfManaged,
    };
    // Recheck system after publication. A concurrently provisioned system root
    // prevents the self claim; the safe, empty self leaf remains non-authoritative.
    if let Some(system) = open_authority_candidate(&system_locator)? {
        return Err(StoreActivationError::SystemAuthorityPresent {
            path: system.authority.path,
        }
        .into());
    }
    let Some(self_managed) = open_authority_candidate(&self_locator)? else {
        return Err(StoreActivationError::AnchorNotProvisioned {
            path: self_locator.path,
        }
        .into());
    };
    if matches!(
        self_managed.state,
        StoreActivationState::Lost | StoreActivationState::CorruptOrReplaced
    ) {
        return Err(StoreActivationError::NotResumable.into());
    }
    if self_managed.claim.is_none()
        && !matches!(self_managed.state, StoreActivationState::NeverActivated)
    {
        return Err(StoreActivationError::AuthorityClaimInvalid {
            path: self_managed.authority.path,
        }
        .into());
    }
    let declared = self_managed.claim.is_none();
    require_current_self_path(&expected_self_path)?;
    ensure_authority_claim(&self_managed.authority, None, self_managed.claim.as_ref())?;
    require_current_self_path(&expected_self_path)?;
    Ok(SelfAuthorityInitializationOutcome {
        provisioning: outcome,
        declared,
    })
}

/// Inspect and select the current account's existing authority without creating
/// an anchor, store, or activation record.
pub fn check_current_euid_authority_readiness()
-> Result<CurrentEuidAuthorityReadiness, StoreActivationError> {
    let selection = select_current_euid_authority()?;
    if selection.mode == ActivationAuthorityMode::SelfManaged
        && selection.selected.claim.is_none()
        && matches!(
            selection.selected.state,
            StoreActivationState::NeverActivated
        )
    {
        return Err(StoreActivationError::SelfInitializationRequired);
    }
    Ok(CurrentEuidAuthorityReadiness {
        mode: selection.mode,
        path: selection.selected.authority.path.clone(),
        backend: selection.selected.authority.backend,
        activation: selection.selected.state.kind(),
    })
}

#[cfg(any(test, feature = "integration-test-anchor"))]
pub(super) fn selection_for_locator(
    locator: &ActivationAnchorLocator,
) -> Result<AuthoritySelection, StoreActivationError> {
    let authority = open_activation_anchor(locator)?;
    let claim = read_optional_authority(&authority).map_err(store_error_from_record_read)?;
    let state = discover_with_authority(&authority)?;
    Ok(AuthoritySelection {
        mode: locator.mode(),
        selected: AuthorityCandidate {
            authority,
            state,
            claim,
        },
        peer: None,
    })
}

pub(super) fn production_authority_selection() -> Result<AuthoritySelection, StoreActivationError> {
    #[cfg(feature = "integration-test-anchor")]
    if let Some(path) = std::env::var_os(INTEGRATION_TEST_ANCHOR_ENV) {
        return selection_for_locator(&ActivationAnchorLocator {
            path: PathBuf::from(path),
            kind: AnchorKind::IntegrationTest,
        });
    }
    select_current_euid_authority()
}

/// Select the fixed current-account authority and activate or resume
/// `desired_store` only when the authenticated selector state permits it.
///
/// This is the sole public mutation adapter. It holds every existing candidate
/// lock through the returned lifecycle lease; callers cannot activate one
/// locator independently and create split authority.
pub fn activate_current_euid_store(
    desired_store: &Path,
) -> Result<MutationStoreActivation, StoreActivationError> {
    activate_authority_selection_with_probe(
        production_authority_selection()?,
        desired_store,
        probe_desired_store_support,
    )
}

pub(super) fn ensure_authority_claim(
    authority: &AuthorityRoot,
    peer: Option<&AuthorityCandidate>,
    existing: Option<&AuthorityRecord>,
) -> Result<AuthorityRecord, StoreActivationError> {
    let prepare = read_optional_prepare(authority).map_err(store_error_from_record_read)?;
    let selection_id = match (existing, prepare.as_ref()) {
        (Some(claim), Some(prepare)) if claim.selection_id != prepare.activation_id => {
            return Err(StoreActivationError::AuthorityClaimInvalid {
                path: authority.path.clone(),
            });
        }
        (Some(claim), _) => claim.selection_id,
        (None, Some(prepare)) => prepare.activation_id,
        (None, None) => {
            let mut id = [0_u8; ACTIVATION_ID_LEN];
            getrandom::fill(&mut id).map_err(StoreActivationError::Random)?;
            id
        }
    };
    let expected = AuthorityRecord {
        selection_id,
        selected_locator: authority.path.clone(),
        selected_identity: authority.identity,
        selected_backend: authority.backend,
    };
    if existing.is_some_and(|claim| claim != &expected) {
        return Err(StoreActivationError::AuthorityClaimInvalid {
            path: authority.path.clone(),
        });
    }
    if let Some(peer) = peer
        && peer.claim.as_ref().is_some_and(|claim| claim != &expected)
    {
        return Err(StoreActivationError::AuthorityClaimInvalid {
            path: peer.authority.path.clone(),
        });
    }
    let bytes = encode_authority(&expected)?;
    // Publish the witness first. A crash can therefore leave either no claim
    // or a witness that names the selected root; it can never leave a newly
    // selected root whose existing peer has no loss evidence.
    if let Some(peer) = peer {
        publish_record(
            &peer.authority.directory,
            &peer.authority.path,
            AUTHORITY_RECORD_NAME,
            &bytes,
            "peer authority witness",
        )?;
    }
    publish_record(
        &authority.directory,
        &authority.path,
        AUTHORITY_RECORD_NAME,
        &bytes,
        "selected authority claim",
    )?;
    Ok(expected)
}
