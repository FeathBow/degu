//! Native action execution substrate: the bounded process runner, the
//! capability-execution bridge, the quota-observation envelope, and the shared
//! action-result contract. Submodules are private; callers use `crate::native`.

mod action;
mod observation;
mod result;
mod runner;

pub(crate) use action::*;
pub(crate) use observation::*;
pub(crate) use result::*;
pub(crate) use runner::*;
