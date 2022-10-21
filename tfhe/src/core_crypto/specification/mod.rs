//! A module containing the specification for the backends of the `concrete` FHE scheme.
//!
//! A backend is expected to provide access to two different families of objects:
//!
//! + __Entities__ which are FHE objects you can manipulate with the library (the data).
//! + __Engines__ which are types you can use to operate on entities (the operators).
//!
//! The specification contains traits for both entities and engines which are then implemented in
//! the backend modules.
//!
//! This module also contains common tools for the concrete packages
//!
//! # Dispersion
//! This module contains the functions used to compute the variance, standard
//! deviation, etc.
//!
//! # Key kinds
//! This module contains types to manage the different kinds of secret keys.
//!
//! # Parameters
//! This module contains structures that wrap unsigned integer parameters of
//! concrete, like the ciphertext dimension or the polynomial degree.

pub mod engines;
pub mod entities;

pub mod dispersion;
pub mod key_kinds;
pub mod parameters;
