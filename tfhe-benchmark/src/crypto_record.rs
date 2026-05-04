//! Internal parameter bundles used by the core_crypto benchmarks.
//!
//! These structs collect the subset of crypto parameters each benchmark needs to set up keys, in a
//! shape that's homogeneous across the various tfhe parameter types (boolean, classic PBS, multi
//! bit, atomic pattern...). They are *not* serialized — the JSON output is now produced by
//! `tfhe-benchmark-parser::write_to_json_unchecked` which only needs the benchmark id, alias, and
//! display name.

use tfhe::core_crypto::prelude::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweCiphertextCount, LweDimension, PolynomialSize, UnsignedInteger,
};

/// Parameters needed for PBS-style core_crypto benchmarks (`ks_bench`, `ks_pbs_bench`,
/// `pbs_bench`).
///
/// Generic over `Scalar` to support both boolean (`u32`) and shortint (`u64`) flows. The two
/// modulus fields are `Option` because boolean parameters don't have a message/carry modulus.
#[derive(Clone, Copy)]
pub struct BenchPbsParams<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
    /// `None` for boolean parameters.
    pub message_modulus: Option<u64>,
    /// `None` for boolean parameters.
    pub carry_modulus: Option<u64>,
}

/// Parameters needed for the packing-keyswitch benchmark in `ks_bench.rs`.
#[derive(Clone, Copy)]
pub struct BenchPackingKsParams<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub packing_ks_glwe_dimension: GlweDimension,
    pub packing_ks_polynomial_size: PolynomialSize,
    pub packing_ks_base_log: DecompositionBaseLog,
    pub packing_ks_level: DecompositionLevelCount,
    pub packing_ks_key_noise_distribution: DynamicDistribution<Scalar>,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

// ---------------------------------------------------------------------------
// boolean conversions
// ---------------------------------------------------------------------------

#[cfg(feature = "boolean")]
mod boolean_impls {
    use super::*;
    use tfhe::boolean::parameters::BooleanParameters;

    impl From<BooleanParameters> for BenchPbsParams<u32> {
        fn from(params: BooleanParameters) -> Self {
            Self {
                lwe_dimension: params.lwe_dimension,
                glwe_dimension: params.glwe_dimension,
                polynomial_size: params.polynomial_size,
                lwe_noise_distribution: params.lwe_noise_distribution,
                glwe_noise_distribution: params.glwe_noise_distribution,
                pbs_base_log: params.pbs_base_log,
                pbs_level: params.pbs_level,
                ks_base_log: params.ks_base_log,
                ks_level: params.ks_level,
                ciphertext_modulus: CiphertextModulus::<u32>::new_native(),
                message_modulus: None,
                carry_modulus: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// shortint conversions
// ---------------------------------------------------------------------------

#[cfg(feature = "shortint")]
mod shortint_impls {
    use super::*;
    use tfhe::shortint::parameters::list_compression::CompressionParameters;
    use tfhe::shortint::{
        AtomicPatternParameters, ClassicPBSParameters, MultiBitPBSParameters, PBSParameters,
    };

    impl From<AtomicPatternParameters> for BenchPbsParams<u64> {
        fn from(params: AtomicPatternParameters) -> Self {
            Self {
                lwe_dimension: params.lwe_dimension(),
                glwe_dimension: params.glwe_dimension(),
                polynomial_size: params.polynomial_size(),
                lwe_noise_distribution: params.lwe_noise_distribution(),
                glwe_noise_distribution: params.glwe_noise_distribution(),
                pbs_base_log: params.pbs_base_log(),
                pbs_level: params.pbs_level(),
                ks_base_log: params.ks_base_log(),
                ks_level: params.ks_level(),
                ciphertext_modulus: params
                    .ciphertext_modulus()
                    .try_to()
                    .expect("failed to convert ciphertext modulus"),
                message_modulus: Some(params.message_modulus().0),
                carry_modulus: Some(params.carry_modulus().0),
            }
        }
    }

    impl From<ClassicPBSParameters> for BenchPbsParams<u64> {
        fn from(params: ClassicPBSParameters) -> Self {
            AtomicPatternParameters::from(params).into()
        }
    }

    impl From<MultiBitPBSParameters> for BenchPbsParams<u64> {
        fn from(params: MultiBitPBSParameters) -> Self {
            AtomicPatternParameters::from(params).into()
        }
    }

    impl From<PBSParameters> for BenchPbsParams<u64> {
        fn from(params: PBSParameters) -> Self {
            AtomicPatternParameters::from(params).into()
        }
    }

    impl From<(CompressionParameters, AtomicPatternParameters)> for BenchPackingKsParams<u64> {
        fn from(
            (comp_params, pbs_params): (CompressionParameters, AtomicPatternParameters),
        ) -> Self {
            Self {
                lwe_dimension: pbs_params.lwe_dimension(),
                lwe_noise_distribution: pbs_params.encryption_noise_distribution(),
                lwe_per_glwe: comp_params.lwe_per_glwe(),
                packing_ks_glwe_dimension: comp_params.packing_ks_glwe_dimension(),
                packing_ks_polynomial_size: comp_params.packing_ks_polynomial_size(),
                packing_ks_base_log: comp_params.packing_ks_base_log(),
                packing_ks_level: comp_params.packing_ks_level(),
                packing_ks_key_noise_distribution: comp_params.packing_ks_key_noise_distribution(),
                ciphertext_modulus: pbs_params
                    .ciphertext_modulus()
                    .try_to()
                    .expect("failed to convert ciphertext modulus"),
            }
        }
    }
}
