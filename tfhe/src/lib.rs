//! Welcome to the TFHE-rs API documentation!
//!
//! TFHE-rs is a fully homomorphic encryption (FHE) library that implements Zama's variant of TFHE.

// Enable pedantic lints
#![warn(clippy::pedantic)]
// The following lints have been temporarily allowed
// They are expected to be fixed progressively
#![allow(clippy::unreadable_literal)] // 830
#![allow(clippy::doc_markdown)] // 688
#![allow(clippy::missing_panics_doc)] // 667
#![allow(clippy::cast_possible_truncation)] // 540
#![allow(clippy::similar_names)] // 514
#![allow(clippy::must_use_candidate)] // 356
#![allow(clippy::wildcard_imports)] // 350
#![allow(clippy::module_name_repetitions)] // 328
#![allow(clippy::cast_lossless)] // 280
#![allow(clippy::missing_const_for_fn)] // 243
#![allow(clippy::missing_errors_doc)] // 118
#![allow(clippy::cast_precision_loss)] // 102
#![allow(clippy::items_after_statements)] // 99
#![allow(clippy::cast_sign_loss)] // 97
#![allow(clippy::inline_always)] // 51
#![allow(clippy::many_single_char_names)] // 44
#![allow(clippy::too_many_lines)] // 34
#![allow(clippy::match_same_arms)] // 19
#![allow(clippy::range_plus_one)] // 16
#![allow(clippy::return_self_not_must_use)] // 11
#![allow(clippy::ignored_unit_patterns)] // 9
#![allow(clippy::large_types_passed_by_value)] // 8
#![allow(clippy::float_cmp)] // 7
#![allow(clippy::bool_to_int_with_if)] // 6
#![allow(clippy::unsafe_derive_deserialize)] // 1
#![allow(clippy::cast_possible_wrap)]
// 1

// These pedantic lints are deemed to bring too little value therefore they are allowed (which are
// their natural state anyways, being pedantic lints)

// Would require a ; for the last statement of a function even if the function returns (), compiler
// indicates it is for formatting consistency, cargo fmt works well with it allowed anyways.
#![allow(clippy::semicolon_if_nothing_returned)]
// Warns when iter or iter_mut are called explicitly, but it reads more nicely e.g. when there are
// parallel and sequential iterators that are mixed
#![allow(clippy::explicit_iter_loop)]
// End allowed pedantic lints

// Nursery lints
#![warn(clippy::nursery)]
// The following lints have been temporarily allowed
// They are expected to be fixed progressively
#![allow(clippy::missing_const_for_fn)] // 243
#![allow(clippy::redundant_pub_crate)] // 116
#![allow(clippy::suboptimal_flops)] // 43
#![allow(clippy::significant_drop_tightening)] // 10
#![allow(clippy::cognitive_complexity)] // 6
#![allow(clippy::iter_with_drain)] // 2
#![allow(clippy::large_stack_frames)] // 1
#![cfg_attr(feature = "__wasm_api", allow(dead_code))]
#![cfg_attr(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        feature = "nightly-avx512"
    ),
    feature(avx512_target_feature, stdarch_x86_avx512)
)]
#![cfg_attr(all(doc, not(doctest)), feature(doc_auto_cfg))]
#![cfg_attr(all(doc, not(doctest)), feature(doc_cfg))]
#![warn(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "__c_api")]
pub mod c_api;

#[cfg(feature = "boolean")]
/// Welcome to the TFHE-rs [`boolean`](`crate::boolean`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod boolean;

/// Welcome to the TFHE-rs [`core_crypto`](`crate::core_crypto`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod core_crypto;

#[cfg(feature = "integer")]
/// Welcome to the TFHE-rs [`integer`](`crate::integer`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod integer;

pub mod backward_compatibility;
#[cfg(feature = "shortint")]
/// Welcome to the TFHE-rs [`shortint`](`crate::shortint`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod shortint;

#[cfg(feature = "pbs-stats")]
pub use shortint::server_key::pbs_stats::*;

#[cfg(feature = "__wasm_api")]
/// cbindgen:ignore
mod js_on_wasm_api;

#[cfg(all(
    doctest,
    feature = "shortint",
    feature = "boolean",
    feature = "integer",
    feature = "zk-pok-experimental"
))]
mod test_user_docs;

#[cfg(feature = "integer")]
/// cbindgen:ignore
pub(crate) mod high_level_api;

#[cfg(feature = "integer")]
pub use high_level_api::*;

#[cfg(any(test, doctest, feature = "internal-keycache"))]
/// cbindgen:ignore
pub mod keycache;

pub mod safe_deserialization;

pub mod conformance;

pub mod named;

pub mod error;
#[cfg(feature = "zk-pok-experimental")]
pub mod zk;

pub use error::{Error, ErrorKind};
pub type Result<T> = std::result::Result<T, Error>;
