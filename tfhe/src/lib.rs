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
#![allow(clippy::semicolon_if_nothing_returned)] // 383
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
#![allow(clippy::unnecessary_wraps)] // 45
#![allow(clippy::many_single_char_names)] // 44
#![allow(clippy::needless_pass_by_value)] // 44
#![allow(clippy::too_many_lines)] // 34
#![allow(clippy::explicit_iter_loop)] // 34
#![allow(clippy::redundant_closure_for_method_calls)] // 32
#![allow(clippy::match_same_arms)] // 19
#![allow(clippy::uninlined_format_args)] // 19
#![allow(clippy::unused_self)] // 17
#![allow(clippy::range_plus_one)] // 16
#![allow(clippy::if_not_else)] // 14
#![allow(clippy::return_self_not_must_use)] // 11
#![allow(clippy::default_trait_access)] // 11
#![allow(clippy::ignored_unit_patterns)] // 9
#![allow(clippy::inconsistent_struct_constructor)] // 9
#![allow(clippy::large_types_passed_by_value)] // 8
#![allow(clippy::float_cmp)] // 7
#![allow(clippy::bool_to_int_with_if)] // 6
#![allow(clippy::implicit_clone)] // 5
#![allow(clippy::trivially_copy_pass_by_ref)] // 5
#![allow(clippy::manual_let_else)] // 4
#![allow(clippy::used_underscore_binding)] // 3
#![allow(clippy::ptr_as_ptr)] // 2
#![allow(clippy::unsafe_derive_deserialize)] // 1
#![allow(clippy::cast_possible_wrap)] // 1
#![cfg_attr(feature = "__wasm_api", allow(dead_code))]
#![cfg_attr(feature = "nightly-avx512", feature(stdsimd, avx512_target_feature))]
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

#[cfg(feature = "shortint")]
/// Welcome to the TFHE-rs [`shortint`](`crate::shortint`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod shortint;

#[cfg(feature = "__wasm_api")]
/// cbindgen:ignore
mod js_on_wasm_api;
#[cfg(feature = "__wasm_api")]
pub use js_on_wasm_api::*;

#[cfg(all(
    doctest,
    feature = "shortint",
    feature = "boolean",
    feature = "integer"
))]
mod test_user_docs;

/// cbindgen:ignore
#[cfg(feature = "integer")]
pub(crate) mod high_level_api;

#[cfg(feature = "integer")]
pub use high_level_api::*;

/// cbindgen:ignore
#[cfg(any(test, doctest, feature = "internal-keycache"))]
pub mod keycache;

#[cfg(feature = "safe-deserialization")]
pub mod safe_deserialization;

pub mod conformance;

pub mod named;
