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
//! ## Montgomery Form Convention
//!
//! All field arithmetic uses Montgomery form internally for efficiency.
//! - **Input**: Points can be in normal form (`points_in_montgomery = false`) or Montgomery form
//!   (`points_in_montgomery = true`)
//! - **Output**: Results from MSM are in Montgomery form
//! - **Conversion**: Use `from_montgomery_normalized()` to convert to normal form
//!
//! ## Thread Safety
//!
//! CUDA operations require stream synchronization. Each CUDA stream should be
//! used by only one thread at a time. The caller is responsible for managing
//! stream lifetime and synchronization.
//!
//! ## Example
//!
//! ```rust,no_run
//! use zk_cuda_backend::{Fp, G1Affine, G1Projective};
//!
//! // Create a G1 affine point
//! let g1_affine = G1Affine::new(
//!     Fp::new([0x1234, 0, 0, 0, 0, 0, 0]), // x coordinate
//!     Fp::new([0x5678, 0, 0, 0, 0, 0, 0]), // y coordinate
//!     false,                               // not at infinity
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

// Auto-generated bindgen bindings (matching tfhe-cuda-backend pattern)
#[allow(warnings)]
pub mod bindings;

pub mod conversions;
pub mod types;

pub use types::*;
// Re-export Fp from bindings module (it's the Fq equivalent - 7-limb field element)
pub use bindings::Fp;

// Re-export Montgomery conversion functions
pub use conversions::{g1_affine_from_montgomery, g2_affine_from_montgomery};

// Re-export conversion functions for arkworks types
pub use conversions::{g1_affine_from_arkworks, g1_projective_to_ffi, g2_projective_to_ffi};
