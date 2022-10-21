#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::missing_safety_doc)]
#[cfg(feature = "boolean-c-api")]
pub mod boolean;
pub mod buffer;
#[cfg(feature = "shortint-c-api")]
pub mod shortint;
pub(crate) mod utils;
