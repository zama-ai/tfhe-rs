//! The standard API for Instant is not available in Wasm runtimes.
//! This module replaces the Instant type from std to a custom implementation.

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::Instant;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use std::time::Instant;
