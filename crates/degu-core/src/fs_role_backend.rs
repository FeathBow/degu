//! Role-specific filesystem backend identities for sealed lifecycle state.
//!
//! The activation anchor, WAL store, and staging mount require different
//! semantics. Their backend identities are therefore distinct types; none can
//! be substituted for another. These values are not live authority: callers
//! must still retain and revalidate the exact held descriptors for the role.

use crate::local_backend::CertifiedLocalBackend;

macro_rules! local_role_backend {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) struct $name(CertifiedLocalBackend);

        impl $name {
            pub(crate) const fn certified_local(backend: CertifiedLocalBackend) -> Self {
                Self(backend)
            }

            pub(crate) const fn local_backend(self) -> CertifiedLocalBackend {
                self.0
            }
        }
    };
}

local_role_backend!(
    /// Backend identity certified for the activation-anchor role.
    ActivationAnchorBackend
);
local_role_backend!(
    /// Backend identity certified for the durable WAL-store role.
    WalStoreBackend
);
local_role_backend!(
    /// Backend identity certified for the sealed-staging mount role.
    StagingMountBackend
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_role_identities_preserve_the_wire_backend() {
        for backend in [
            CertifiedLocalBackend::Ext4,
            CertifiedLocalBackend::Xfs,
            CertifiedLocalBackend::Apfs,
        ] {
            assert_eq!(
                ActivationAnchorBackend::certified_local(backend).local_backend(),
                backend
            );
            assert_eq!(
                WalStoreBackend::certified_local(backend).local_backend(),
                backend
            );
            assert_eq!(
                StagingMountBackend::certified_local(backend).local_backend(),
                backend
            );
        }
    }
}
