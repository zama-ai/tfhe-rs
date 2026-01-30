//! Rust API for BLS12-446 curve operations
//!
//! This crate provides Rust bindings for CUDA-accelerated BLS12-446 curve operations,
//! including multi-scalar multiplication (MSM) for G1 and G2 points.
//!
//! ## Overview
//!
//! The API exposes G1 and G2 points in both affine and projective coordinates,
//! with conversion functions for arkworks types.
//!
//! ## Example
//!
//! ```rust,no_run
//! use zk_cuda_backend::{G1Affine, G1Projective};
//!
//! // Create a G1 affine point
//! let g1_affine = G1Affine::new(
//!     [0x1234, 0, 0, 0, 0, 0, 0], // x coordinate
//!     [0x5678, 0, 0, 0, 0, 0, 0], // y coordinate
//!     false,                      // not at infinity
//! );
//!
//! // Convert to projective coordinates
//! let g1_proj = g1_affine.to_projective();
//!
//! // Convert back to affine
//! let g1_affine_again = g1_proj.to_affine();
//! ```

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Force linking of tfhe-cuda-backend which provides device utilities (cuda_malloc, cuda_set_device,
// etc.)
extern crate tfhe_cuda_backend;

pub mod conversions;
pub mod ffi;
pub mod types;

#[cfg(test)]
mod tests;

pub use types::*;
// Re-export Fp from ffi module (it's the Fq equivalent - 7-limb field element)
pub use ffi::Fp;

// Re-export Montgomery conversion functions
pub use conversions::{g1_affine_from_montgomery, g2_affine_from_montgomery};

// Re-export conversion functions for arkworks types
pub use conversions::{g1_affine_from_arkworks, g1_projective_to_limbs, g2_projective_to_limbs};
