//! A module containing various backends implementing various FHE cryptographic primitives.

#[cfg(feature = "backend_default")]
pub mod default;

#[cfg(feature = "backend_fft")]
pub mod fft;

#[cfg(feature = "backend_cuda")]
pub mod cuda;
