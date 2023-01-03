//! Welcome to the TFHE-rs `core_crypto` module documentation!
//!
//! This library contains a set of low-level primitives which can be used to implement *Fully
//! Homomorphically Encrypted* (FHE) programs. In a nutshell, fully homomorphic encryption makes it
//! possible to perform arbitrary computations over encrypted data. With FHE, you can perform
//! computations without putting your trust on third-party computation providers.
//!
//! # Audience
//!
//! This library is geared towards people who already know their way around FHE. It gives the user
//! freedom of choice over a breadth of parameters, which can lead to less than 128 bits of security
//! if chosen incorrectly
pub mod algorithms;
pub mod commons;
pub mod entities;
pub mod prelude;
pub mod seeders;

// TODO REFACTOR
// For now this module is not refactored, it contains high performance code and will be refactored
// at a later stage. It is self contained, allowing to put it in its own module in the meantime.
pub mod fft_impl;
