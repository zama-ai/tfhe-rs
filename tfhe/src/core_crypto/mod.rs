#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(
    feature = "backend_fft_nightly_avx512",
    feature(stdsimd, avx512_target_feature)
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! Welcome to the `concrete-core` documentation!
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
//! Fortunately, we propose multiple libraries that build on top of `concrete-core` and which
//! propose a safer API. To see which one best suits your needs, see the
//! [concrete homepage](https://zama.ai/concrete).
//!
//! # Architecture
//!
//! `concrete-core` is a modular library which makes it possible to use different backends to
//! perform FHE operations. Its design revolves around two modules:
//!
//! + The [`specification`] module contains a specification (in the form of traits) of the
//! `concrete` FHE scheme. It describes the FHE objects and operators, which are exposed by the
//! library.
//! + The [`backends`] module contains various backends implementing all or a part of this scheme.
//! These different backends can be activated by feature flags, each making use of different
//! hardware or system libraries to make the operations faster.
//!
//! # Activating backends
//!
//! The different backends can be activated using the feature flags `backend_*`. The `backend_core`
//! contains an engine executing operations on a single thread of the cpu. It is activated by
//! default.
//!
//! # Navigating the code
//!
//! If this is your first time looking at the `concrete-core` code-base, it may be simpler for you
//! to first have a look at the [`specification`] module, which contains explanations on the
//! abstract API, and navigate from there.

pub mod backends;
#[doc(hidden)]
pub mod commons;
pub mod prelude;
pub mod specification;
