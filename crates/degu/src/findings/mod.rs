//! Findings selection and presentation: the filter predicates, the shared
//! filter configuration, and the table renderer. Submodules are private;
//! callers use `crate::findings`.

mod filter;
mod filters;
pub(crate) mod table;

pub(crate) use filter::*;
pub(crate) use filters::*;
pub(crate) use table::*;
