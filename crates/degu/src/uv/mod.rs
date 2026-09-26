//! uv-specific reclaim authority built on `crate::native`: the executable
//! version proof, the sealed cache-root traversal authority, the exact prune
//! plan and its consuming execution. Submodules
//! are private; callers use `crate::uv`.

mod executable;
mod plan;
mod root;

#[cfg(target_os = "macos")]
pub(crate) use crate::acl::grants_mutation;
pub(crate) use executable::*;
pub(crate) use plan::*;
pub(crate) use root::*;
