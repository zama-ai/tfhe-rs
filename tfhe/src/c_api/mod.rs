#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::missing_safety_doc)]
#[cfg(feature = "booleans-c-api")]
pub mod booleans;
#[cfg(feature = "shortints-c-api")]
pub mod shortints;
pub mod buffer;
pub(crate) mod utils;
