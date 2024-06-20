//! This module contains algorithms manipulating FHE entities as well as some convenience algorithms
//! operating on [`slices of scalars`](`slice_algorithms`) and on
//! [`polynomials`](`polynomial_algorithms`).

pub mod ggsw_conversion;
pub mod ggsw_encryption;
pub mod glwe_encryption;
pub mod glwe_linear_algebra;
pub mod glwe_sample_extraction;
pub mod glwe_secret_key_generation;
pub mod lwe_bootstrap_key_conversion;
pub mod lwe_bootstrap_key_generation;
pub mod lwe_compact_ciphertext_list_expansion;
pub mod lwe_compact_public_key_generation;
pub mod lwe_encryption;
pub mod lwe_keyswitch;
pub mod lwe_keyswitch_key_generation;
pub mod lwe_linear_algebra;
pub mod lwe_multi_bit_bootstrap_key_conversion;
pub mod lwe_multi_bit_bootstrap_key_generation;
pub mod lwe_multi_bit_programmable_bootstrapping;
pub mod lwe_packing_keyswitch;
pub mod lwe_packing_keyswitch_key_generation;
pub mod lwe_private_functional_packing_keyswitch;
pub mod lwe_private_functional_packing_keyswitch_key_generation;
pub mod lwe_programmable_bootstrapping;
pub mod lwe_public_key_generation;
pub mod lwe_secret_key_generation;
pub mod lwe_wopbs;
#[cfg(feature = "zk-pok")]
pub mod lwe_zero_knowledge_verification;
pub mod misc;
pub mod polynomial_algorithms;
pub mod seeded_ggsw_ciphertext_decompression;
pub mod seeded_ggsw_ciphertext_list_decompression;
pub mod seeded_glwe_ciphertext_decompression;
pub mod seeded_glwe_ciphertext_list_decompression;
pub mod seeded_lwe_bootstrap_key_decompression;
pub mod seeded_lwe_ciphertext_decompression;
pub mod seeded_lwe_ciphertext_list_decompression;
pub mod seeded_lwe_compact_public_key_decompression;
pub mod seeded_lwe_keyswitch_key_decompression;
pub mod seeded_lwe_multi_bit_bootstrap_key_decompression;
pub mod seeded_lwe_packing_keyswitch_key_decompression;
pub mod seeded_lwe_public_key_decompression;
pub mod slice_algorithms;

#[cfg(test)]
pub(crate) mod test;

// No pub use for slice and polynomial algorithms which would not interest higher level users
// They can still be used via `use crate::core_crypto::algorithms::slice_algorithms::*;`
pub use ggsw_conversion::*;
pub use ggsw_encryption::*;
pub use glwe_encryption::*;
pub use glwe_linear_algebra::*;
pub use glwe_sample_extraction::*;
pub use glwe_secret_key_generation::*;
pub use lwe_bootstrap_key_conversion::*;
pub use lwe_bootstrap_key_generation::*;
pub use lwe_compact_ciphertext_list_expansion::*;
pub use lwe_compact_public_key_generation::*;
pub use lwe_encryption::*;
pub use lwe_keyswitch::*;
pub use lwe_keyswitch_key_generation::*;
pub use lwe_linear_algebra::*;
pub use lwe_multi_bit_bootstrap_key_conversion::*;
pub use lwe_multi_bit_bootstrap_key_generation::*;
pub use lwe_multi_bit_programmable_bootstrapping::*;
pub use lwe_packing_keyswitch::*;
pub use lwe_packing_keyswitch_key_generation::*;
pub use lwe_private_functional_packing_keyswitch::*;
pub use lwe_private_functional_packing_keyswitch_key_generation::*;
pub use lwe_programmable_bootstrapping::*;
pub use lwe_public_key_generation::*;
pub use lwe_secret_key_generation::*;
pub use lwe_wopbs::*;
#[cfg(feature = "zk-pok")]
pub use lwe_zero_knowledge_verification::*;
pub use seeded_ggsw_ciphertext_decompression::*;
pub use seeded_ggsw_ciphertext_list_decompression::*;
pub use seeded_glwe_ciphertext_decompression::*;
pub use seeded_glwe_ciphertext_list_decompression::*;
pub use seeded_lwe_bootstrap_key_decompression::*;
pub use seeded_lwe_ciphertext_decompression::*;
pub use seeded_lwe_ciphertext_list_decompression::*;
pub use seeded_lwe_compact_public_key_decompression::*;
pub use seeded_lwe_keyswitch_key_decompression::*;
pub use seeded_lwe_multi_bit_bootstrap_key_decompression::*;
pub use seeded_lwe_packing_keyswitch_key_decompression::*;
pub use seeded_lwe_public_key_decompression::*;
