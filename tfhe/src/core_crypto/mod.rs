#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! Welcome to the tfhe.rs `core_crypto` module documentation!
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
//!
//! # Architecture
//!
//! `core_crypto` is modular which makes it possible to use different backends to perform FHE
//! operations. Its design revolves around two modules:
//!
//! + The [`specification`](crate::core_crypto::specification) module contains a specification (in
//! the form of traits) of Zama's variant of the TFHE scheme. It describes the FHE objects and
//! operators, which are exposed by the library.
//! + The [`backends`](crate::core_crypto::backends) module contains various backends implementing
//! all or a part of this scheme. These different backends can be activated by feature flags, each
//! making use of different hardware or system libraries to make the operations faster.
//!
//! # Activating backends
//!
//! The different backends can be activated using the feature flags `backend_*`. The `backend_core`
//! contains an engine executing operations on a single thread of the cpu. It is activated by
//! default.
//!
//! # Navigating the code
//!
//! If this is your first time looking at the `core_crypto` module code, it may be simpler for you
//! to first have a look at the [`specification`](crate::core_crypto::specification) module, which
//! contains explanations on the abstract API, and navigate from there.

pub mod backends;
#[doc(hidden)]
pub mod commons;
pub mod prelude;
pub mod specification;

// Modules part of the refactoring effort
pub mod algorithms;
pub mod entities;
// TODO REFACTOR
// For now this module is not refactored, it contains high performance code and will be refactored
// at a later stage. It is self contained, allowing to put it in its own module in the meantime.
pub mod fft_impl;
