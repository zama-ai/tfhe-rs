//! Experimental and legacy features built on top of `tfhe`.
//!
//! Nothing in this crate is meant for production use: APIs may change or be removed without
//! notice and are not covered by the stability or security guarantees of `tfhe`.
//!
//! This crate depends on `tfhe` and only uses its public API; `tfhe` never depends on it.

#[cfg(feature = "boolean")]
pub mod boolean;
