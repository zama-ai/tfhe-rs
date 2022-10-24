#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::missing_safety_doc)]
pub mod booleans;
#[cfg(any(
    feature = "backend_default_serialization",
    feature = "backend_fft_serialization"
))]
pub mod buffer;
pub(crate) mod utils;
