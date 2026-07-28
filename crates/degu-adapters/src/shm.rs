#[cfg(target_os = "linux")]
#[path = "shm/linux.rs"]
mod imp;
#[cfg(not(target_os = "linux"))]
#[path = "shm/unsupported.rs"]
mod imp;

#[cfg(all(test, unix, not(target_os = "linux")))]
#[allow(
    dead_code,
    reason = "compile-check the Linux implementation on other Unix targets"
)]
#[path = "shm/linux.rs"]
mod linux_compile;

pub use imp::Shm;

use degu_core::finding::{FindingFacts, Ownership, Recovery};

const FACTS: FindingFacts = (Recovery::UserAsset, Ownership::Standalone, None);
