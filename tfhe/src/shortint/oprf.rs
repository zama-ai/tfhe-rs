use tfhe_versionable::Versionize;

use crate::named::Named;

use super::backward_compatibility::oprf::*;
use super::client_key::atomic_pattern::AtomicPatternClientKey;
use super::server_key::LookupTableSize;
use super::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::math::random::{RandomGenerator, Uniform};
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::*;
use crate::shortint::atomic_pattern::{AtomicPattern, AtomicPatternServerKey};
use crate::shortint::ciphertext::{Degree, ReRandomizationHashAlgo, ReRandomizationSeed};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::key_switching_key::KeySwitchingKeyMaterialView;
use crate::shortint::parameters::{KeySwitch32PBSParameters, NoiseLevel};
use crate::shortint::public_key::CompactPublicKey;
use crate::shortint::server_key::{
    apply_multi_bit_blind_rotate, apply_standard_blind_rotate, generate_lookup_table_no_encode,
    LookupTableOwned, PBSConformanceParams, PbsTypeConformanceParams, ShortintBootstrappingKey,
};
use crate::shortint::{AtomicPatternParameters, ClientKey, PBSParameters, ServerKey};
use aligned_vec::ABox;
use core::num::NonZeroU64;
use itertools::Itertools;
use rayon::prelude::*;
use sha3::digest::Digest;
use tfhe_csprng::seeders::{Seed, XofSeed};
use tfhe_fft::c64;

/// Types that can be converted into a byte seed for the OPRF functions.
///
/// This trait abstracts over the two common ways to specify a seed for the
/// `generate_oblivious_pseudo_random*` family of functions across the
/// `shortint`, `integer` and high-level APIs:
///
/// - a [`Seed`] (a wrapper around `u128`), and
/// - any byte-like reference such as `&[u8]`, `&[u8; N]`, `&Vec<u8>`
pub trait OprfSeed {
    type Bytes: AsRef<[u8]>;

    fn into_bytes(self) -> Self::Bytes;
}

impl OprfSeed for Seed {
    type Bytes = [u8; 16];

    fn into_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}

impl<'a> OprfSeed for &'a [u8] {
    type Bytes = &'a [u8];

    fn into_bytes(self) -> &'a [u8] {
        self
    }
}

impl<'a> OprfSeed for &'a Vec<u8> {
    type Bytes = &'a [u8];

    fn into_bytes(self) -> &'a [u8] {
        self.as_slice()
    }
}

impl OprfSeed for Vec<u8> {
    type Bytes = Self;

    fn into_bytes(self) -> Self {
        self
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(AtomicPatternOprfPrivateKeyVersions)]
pub enum AtomicPatternOprfPrivateKey {
    Standard(LweSecretKeyOwned<u64>),
    KeySwitch32(LweSecretKeyOwned<u32>),
}

/// Dedicated private key for OPRF functions
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(OprfPrivateKeyVersions)]
pub struct OprfPrivateKey(pub(crate) AtomicPatternOprfPrivateKey);

impl OprfPrivateKey {
    /// Create a new private key, this uses the same parameters as the bootstrap key used for
    /// compute
    pub fn new(target_ck: &ClientKey) -> Self {
        match &target_ck.atomic_pattern {
            AtomicPatternClientKey::Standard(std) => {
                let lwe_sk = ShortintEngine::with_thread_local_mut(|engine| {
                    allocate_and_generate_new_binary_lwe_secret_key(
                        std.parameters.lwe_dimension(),
                        &mut engine.secret_generator,
                    )
                });
                Self(AtomicPatternOprfPrivateKey::Standard(lwe_sk))
            }
            AtomicPatternClientKey::KeySwitch32(ks32) => {
                let lwe_sk = ShortintEngine::with_thread_local_mut(|engine| {
                    allocate_and_generate_new_binary_lwe_secret_key(
                        ks32.parameters.lwe_dimension(),
                        &mut engine.secret_generator,
                    )
                });
                Self(AtomicPatternOprfPrivateKey::KeySwitch32(lwe_sk))
            }
        }
    }

    pub fn from_raw_parts(sk: AtomicPatternOprfPrivateKey) -> Self {
        Self(sk)
    }

    pub fn into_raw_parts(self) -> AtomicPatternOprfPrivateKey {
        self.0
    }
}

// ============================================================================
// OprfBootstrappingKey: the dedicated Fourier BSK for OPRF (no modulus switch config)
// ============================================================================

/// Bootstrapping Key with elements in the Fourier domain, dedicated to OPRF.
///
/// Different from `ShortintBootstrappingKey` as the PRF does not use modulus switch
/// and so not having to carry the extra Type associated to the modulus switched type of
/// ShortintBootstrappingKey makes things lighter
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(OprfBootstrappingKeyVersions)]
pub enum OprfBootstrappingKey<C: Container<Element = c64>> {
    Classic {
        bsk: FourierLweBootstrapKey<C>,
    },
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKey<C>,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

pub type OprfBootstrappingKeyOwned = OprfBootstrappingKey<ABox<[c64]>>;
pub type OprfBootstrappingKeyView<'a> = OprfBootstrappingKey<&'a [c64]>;

impl<C: Container<Element = c64>> OprfBootstrappingKey<C> {
    pub(crate) fn input_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic { bsk } => bsk.input_lwe_dimension(),
            Self::MultiBit { fourier_bsk, .. } => fourier_bsk.input_lwe_dimension(),
        }
    }

    pub(crate) fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic { bsk } => bsk.polynomial_size(),
            Self::MultiBit { fourier_bsk, .. } => fourier_bsk.polynomial_size(),
        }
    }

    pub(crate) fn glwe_size(&self) -> GlweSize {
        match self {
            Self::Classic { bsk } => bsk.glwe_size(),
            Self::MultiBit { fourier_bsk, .. } => fourier_bsk.glwe_size(),
        }
    }

    pub(crate) fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic { bsk } => bsk.output_lwe_dimension(),
            Self::MultiBit { fourier_bsk, .. } => fourier_bsk.output_lwe_dimension(),
        }
    }

    fn assert_compatible_with_target_bsk<T: UnsignedInteger>(
        &self,
        target_bsk: &ShortintBootstrappingKey<T>,
    ) {
        assert_eq!(target_bsk.input_lwe_dimension(), self.input_lwe_dimension());
        assert_eq!(
            target_bsk.output_lwe_dimension(),
            self.output_lwe_dimension()
        );
        assert_eq!(target_bsk.polynomial_size(), self.polynomial_size());
        assert_eq!(target_bsk.glwe_size(), self.glwe_size());
    }
}

impl OprfBootstrappingKeyOwned {
    pub fn as_view(&self) -> OprfBootstrappingKeyView<'_> {
        match self {
            Self::Classic { bsk } => OprfBootstrappingKeyView::Classic { bsk: bsk.as_view() },
            Self::MultiBit {
                fourier_bsk,
                thread_count,
                deterministic_execution,
            } => OprfBootstrappingKeyView::MultiBit {
                fourier_bsk: fourier_bsk.as_view(),
                thread_count: *thread_count,
                deterministic_execution: *deterministic_execution,
            },
        }
    }
}

impl ParameterSetConformant for OprfBootstrappingKeyOwned {
    type ParameterSet = PBSConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, &parameter_set.pbs_type) {
            (Self::Classic { bsk }, PbsTypeConformanceParams::Classic { .. }) => {
                let param: LweBootstrapKeyConformanceParams<_> = parameter_set.into();
                bsk.is_conformant(&param)
            }
            (
                Self::MultiBit {
                    fourier_bsk,
                    thread_count: _,
                    deterministic_execution: _,
                },
                PbsTypeConformanceParams::MultiBit { .. },
            ) => MultiBitBootstrapKeyConformanceParams::try_from(parameter_set)
                .is_ok_and(|param| fourier_bsk.is_conformant(&param)),
            _ => false,
        }
    }
}

// ============================================================================
// ExpandedOprfBootstrappingKey: standard domain BSK with expand -> Fourier
// ============================================================================

/// Bootstrapping Key with elements in the standard (i.e not fourier) domain
#[derive(PartialEq, Eq)]
pub enum ExpandedOprfBootstrappingKey {
    Classic {
        bsk: LweBootstrapKeyOwned<u64>,
    },
    MultiBit {
        bsk: LweMultiBitBootstrapKeyOwned<u64>,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

impl ExpandedOprfBootstrappingKey {
    pub fn to_fourier(&self) -> OprfBootstrappingKeyOwned {
        match self {
            Self::Classic { bsk } => {
                let mut fourier_bsk = FourierLweBootstrapKeyOwned::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                );
                par_convert_standard_lwe_bootstrap_key_to_fourier(bsk, &mut fourier_bsk);
                OprfBootstrappingKey::Classic { bsk: fourier_bsk }
            }
            Self::MultiBit {
                bsk,
                thread_count,
                deterministic_execution,
            } => {
                let mut fourier_bsk = FourierLweMultiBitBootstrapKey::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                    bsk.grouping_factor(),
                );

                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(bsk, &mut fourier_bsk);

                OprfBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count: *thread_count,
                    deterministic_execution: *deterministic_execution,
                }
            }
        }
    }
}

// ============================================================================
// ExpandedOprfServerKey
// ============================================================================

#[derive(PartialEq, Eq)]
pub struct ExpandedOprfServerKey(pub(crate) ExpandedOprfBootstrappingKey);

impl ExpandedOprfServerKey {
    pub fn from_raw_parts(inner: ExpandedOprfBootstrappingKey) -> Self {
        Self(inner)
    }

    pub fn into_raw_parts(self) -> ExpandedOprfBootstrappingKey {
        self.0
    }

    pub fn to_fourier(&self) -> OprfServerKey {
        GenericOprfServerKey {
            inner: self.0.to_fourier(),
        }
    }
}

// ============================================================================
// CompressedOprfBootstrappingKey: seeded BSK
// ============================================================================

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedOprfBootstrappingKeyVersions)]
pub enum CompressedOprfBootstrappingKey {
    Classic {
        seeded_bsk: SeededLweBootstrapKeyOwned<u64>,
    },
    MultiBit {
        seeded_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
        deterministic_execution: bool,
    },
}

impl CompressedOprfBootstrappingKey {
    pub fn expand(&self) -> ExpandedOprfBootstrappingKey {
        match self {
            Self::Classic { seeded_bsk } => {
                let core_bsk = seeded_bsk.as_view().par_decompress_into_lwe_bootstrap_key();
                ExpandedOprfBootstrappingKey::Classic { bsk: core_bsk }
            }
            Self::MultiBit {
                seeded_bsk,
                deterministic_execution,
            } => {
                let core_bsk = seeded_bsk
                    .as_view()
                    .par_decompress_into_lwe_multi_bit_bootstrap_key();

                let thread_count = ShortintEngine::get_thread_count_for_multi_bit_pbs(
                    core_bsk.input_lwe_dimension(),
                    core_bsk.glwe_size().to_glwe_dimension(),
                    core_bsk.polynomial_size(),
                    core_bsk.decomposition_base_log(),
                    core_bsk.decomposition_level_count(),
                    core_bsk.grouping_factor(),
                );

                ExpandedOprfBootstrappingKey::MultiBit {
                    bsk: core_bsk,
                    thread_count,
                    deterministic_execution: *deterministic_execution,
                }
            }
        }
    }
}

impl ParameterSetConformant for CompressedOprfBootstrappingKey {
    type ParameterSet = PBSConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, &parameter_set.pbs_type) {
            (Self::Classic { seeded_bsk }, PbsTypeConformanceParams::Classic { .. }) => {
                let param: LweBootstrapKeyConformanceParams<_> = parameter_set.into();
                seeded_bsk.is_conformant(&param)
            }
            (
                Self::MultiBit {
                    seeded_bsk,
                    deterministic_execution: _,
                },
                PbsTypeConformanceParams::MultiBit { .. },
            ) => MultiBitBootstrapKeyConformanceParams::try_from(parameter_set)
                .is_ok_and(|param| seeded_bsk.is_conformant(&param)),
            _ => false,
        }
    }
}

// ============================================================================
// CompressedOprfServerKey
// ============================================================================

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedOprfServerKeyVersions)]
pub struct CompressedOprfServerKey {
    pub(crate) inner: CompressedOprfBootstrappingKey,
}

impl CompressedOprfServerKey {
    pub fn new(sk: &OprfPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        let inner = match (&sk.0, &target_ck.atomic_pattern) {
            (
                AtomicPatternOprfPrivateKey::KeySwitch32(sk),
                AtomicPatternClientKey::KeySwitch32(ck),
            ) => ShortintEngine::with_thread_local_mut(|engine| {
                engine.new_compressed_oprf_bootstrapping_key_ks32(
                    ck.parameters,
                    sk,
                    &ck.glwe_secret_key,
                )
            }),
            (AtomicPatternOprfPrivateKey::Standard(sk), AtomicPatternClientKey::Standard(ck)) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    engine.new_compressed_oprf_bootstrapping_key_standard(
                        ck.parameters,
                        sk,
                        &ck.glwe_secret_key,
                    )
                })
            }
            _ => {
                return Err(crate::error!(
                    "Mismatched atomic_patterns for oprf key and client key"
                ))
            }
        };

        Ok(Self { inner })
    }

    pub fn from_raw_parts(inner: CompressedOprfBootstrappingKey) -> Self {
        Self { inner }
    }

    pub fn into_raw_parts(self) -> CompressedOprfBootstrappingKey {
        self.inner
    }

    pub fn expand(&self) -> ExpandedOprfServerKey {
        ExpandedOprfServerKey(self.inner.expand())
    }
}

impl ParameterSetConformant for CompressedOprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let pbs_conformance_params: PBSConformanceParams = match parameter_set {
            AtomicPatternParameters::Standard(std_params) => std_params.into(),
            AtomicPatternParameters::KeySwitch32(ks32_params) => ks32_params.into(),
        };
        self.inner.is_conformant(&pbs_conformance_params)
    }
}

// ============================================================================
// ShortintEngine helper methods for OPRF key generation
// ============================================================================

impl ShortintEngine {
    fn new_compressed_oprf_bootstrapping_key_ks32<
        InKeycont: Container<Element = u32> + Sync,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params: KeySwitch32PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> CompressedOprfBootstrappingKey {
        let seeded_bsk = self.new_compressed_classic_bootstrapping_key(
            in_key,
            out_key,
            pbs_params.glwe_noise_distribution,
            pbs_params.pbs_base_log,
            pbs_params.pbs_level,
            pbs_params.ciphertext_modulus,
        );
        CompressedOprfBootstrappingKey::Classic { seeded_bsk }
    }

    fn new_oprf_bootstrapping_key_ks32<
        InKeycont: Container<Element = u32> + Sync,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params: KeySwitch32PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> OprfBootstrappingKeyOwned {
        let bsk = self.new_classic_bootstrapping_key(
            in_key,
            out_key,
            pbs_params.glwe_noise_distribution,
            pbs_params.pbs_base_log,
            pbs_params.pbs_level,
            pbs_params.ciphertext_modulus,
        );
        OprfBootstrappingKey::Classic { bsk }
    }

    fn new_oprf_bootstrapping_key_standard<
        InKeycont: Container<Element = u64>,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params: PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> OprfBootstrappingKeyOwned {
        match pbs_params {
            PBSParameters::PBS(pbs_params) => {
                let bsk = self.new_classic_bootstrapping_key(
                    in_key,
                    out_key,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.ciphertext_modulus,
                );

                OprfBootstrappingKey::Classic { bsk }
            }
            PBSParameters::MultiBitPBS(pbs_params) => {
                let fourier_bsk = self.new_multibit_bootstrapping_key(
                    in_key,
                    out_key,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.grouping_factor,
                    pbs_params.ciphertext_modulus,
                );

                let thread_count = Self::get_thread_count_for_multi_bit_pbs(
                    pbs_params.lwe_dimension,
                    pbs_params.glwe_dimension,
                    pbs_params.polynomial_size,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.grouping_factor,
                );
                OprfBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution: pbs_params.deterministic_execution,
                }
            }
        }
    }

    fn new_compressed_oprf_bootstrapping_key_standard<
        InKeycont: Container<Element = u64>,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params: PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> CompressedOprfBootstrappingKey {
        match pbs_params {
            PBSParameters::PBS(pbs_params) => {
                let seeded_bsk = self.new_compressed_classic_bootstrapping_key(
                    in_key,
                    out_key,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.ciphertext_modulus,
                );

                CompressedOprfBootstrappingKey::Classic { seeded_bsk }
            }
            PBSParameters::MultiBitPBS(pbs_params) => {
                let seeded_bsk = par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                    in_key,
                    out_key,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.grouping_factor,
                    pbs_params.ciphertext_modulus,
                    &mut self.seeder,
                );

                CompressedOprfBootstrappingKey::MultiBit {
                    seeded_bsk,
                    deterministic_execution: pbs_params.deterministic_execution,
                }
            }
        }
    }
}

// ============================================================================
// GenericOprfServerKey
// ============================================================================

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(GenericOprfServerKeyVersions)]
pub struct GenericOprfServerKey<C: Container<Element = c64>> {
    pub(crate) inner: OprfBootstrappingKey<C>,
}

pub type OprfServerKey = GenericOprfServerKey<ABox<[c64]>>;
pub type OprfServerKeyView<'a> = GenericOprfServerKey<&'a [c64]>;

// Shared methods for both owned and view types.
impl<C: Container<Element = c64> + Sync> GenericOprfServerKey<C> {
    pub fn from_raw_parts(inner: OprfBootstrappingKey<C>) -> Self {
        Self { inner }
    }

    pub fn into_raw_parts(self) -> OprfBootstrappingKey<C> {
        self.inner
    }

    /// Uniformly generates a batch of encrypted random bit-chunks from a single seed in one call.
    ///
    /// For each entry `bc` in `bit_chunks`, returns a `Vec<Ciphertext>`
    /// of `ceil(bc / random_bits_per_block)` blocks, where `random_bits_per_block`
    /// is the message-modulus log2. Within each chunk, every ciphertext encrypts a
    /// value in `[0, 2^random_bits_per_block[` except for the last one, which may
    /// hold fewer random bits if `bc` does not divide evenly.
    ///
    /// # Panics
    ///
    /// * Panics if `bit_chunks` contains a 0
    /// * Panics if `self` is not compatible with `target_sks`
    pub fn generate_oblivious_pseudo_random_bits_chunks(
        &self,
        seed: impl OprfSeed,
        bit_chunks: &[u64],
        target_sks: &ServerKey,
    ) -> Vec<Vec<Ciphertext>> {
        self.inner.generate_pseudo_random_bits_chunks(
            seed,
            bit_chunks,
            target_sks.message_modulus.0.ilog2() as u64,
            target_sks,
        )
    }

    /// Same as [`Self::generate_oblivious_pseudo_random_bits_chunks`], but applies re-randomization
    /// to the encrypted outputs before returning them. The PRF output is deterministic, the input
    /// `prf_seed` therefore needs to change for each call.
    ///
    /// `compact_public_key` and `key_switching_key_material` are the necessary keys for
    /// re-randomization.
    ///
    /// For each entry `bc` in `bit_chunks`, returns a `Vec<Ciphertext>`
    /// of `ceil(bc / random_bits_per_block)` blocks, where `random_bits_per_block`
    /// is the message-modulus log2. Within each chunk, every ciphertext encrypts a
    /// value in `[0, 2^random_bits_per_block[` except for the last one, which may
    /// hold fewer random bits if `bc` does not divide evenly.
    ///
    /// # Errors
    ///
    /// * Returns `Err` if the supplied `compact_public_key` / `key_switching_key_material` are
    ///   incompatible with the PRF outputs.
    ///
    /// # Panics
    ///
    /// * Panics if `self` is not compatible with `target_sks`.
    /// * Panics if `bit_chunks` contains a `0`.
    pub fn generate_oblivious_pseudo_random_bits_chunks_and_re_randomize(
        &self,
        prf_seed: impl OprfSeed,
        bit_chunks: &[u64],
        target_sks: &ServerKey,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: Option<&KeySwitchingKeyMaterialView>,
        rerand_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<Vec<Vec<Ciphertext>>> {
        self.inner
            .generate_pseudo_random_bits_chunks_and_re_randomize(
                prf_seed,
                bit_chunks,
                target_sks.message_modulus.0.ilog2() as u64,
                target_sks,
                compact_public_key,
                key_switching_key_material,
                rerand_hash_algo,
            )
    }
}

// Owned-only methods.
impl OprfServerKey {
    pub fn new(sk: &OprfPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        let inner = match (&sk.0, &target_ck.atomic_pattern) {
            (
                AtomicPatternOprfPrivateKey::KeySwitch32(sk),
                AtomicPatternClientKey::KeySwitch32(ck),
            ) => ShortintEngine::with_thread_local_mut(|engine| {
                engine.new_oprf_bootstrapping_key_ks32(ck.parameters, sk, &ck.glwe_secret_key)
            }),
            (AtomicPatternOprfPrivateKey::Standard(sk), AtomicPatternClientKey::Standard(ck)) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    engine.new_oprf_bootstrapping_key_standard(
                        ck.parameters,
                        sk,
                        &ck.glwe_secret_key,
                    )
                })
            }
            _ => {
                return Err(crate::error!(
                    "Mismatched atomic_patterns for oprf key and client key"
                ))
            }
        };

        Ok(Self { inner })
    }

    pub fn as_view(&self) -> OprfServerKeyView<'_> {
        GenericOprfServerKey {
            inner: self.inner.as_view(),
        }
    }
}

impl ParameterSetConformant for OprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let pbs_conformance_params: PBSConformanceParams = match parameter_set {
            AtomicPatternParameters::Standard(std_params) => std_params.into(),
            AtomicPatternParameters::KeySwitch32(ks32_params) => ks32_params.into(),
        };
        self.inner.is_conformant(&pbs_conformance_params)
    }
}

// ============================================================================
// Named impls
// ============================================================================

impl Named for AtomicPatternOprfPrivateKey {
    const NAME: &'static str = "shortint::AtomicPatternOprfPrivateKey";
}

impl Named for OprfPrivateKey {
    const NAME: &'static str = "shortint::OprfPrivateKey";
}

impl<C: Container<Element = c64>> Named for OprfBootstrappingKey<C> {
    const NAME: &'static str = "shortint::OprfBootstrappingKey";
}

impl<C: Container<Element = c64>> Named for GenericOprfServerKey<C> {
    const NAME: &'static str = "shortint::GenericOprfServerKey";
}

impl Named for CompressedOprfBootstrappingKey {
    const NAME: &'static str = "shortint::CompressedOprfBootstrappingKey";
}

impl Named for CompressedOprfServerKey {
    const NAME: &'static str = "shortint::CompressedOprfServerKey";
}

// ============================================================================
// PrfSeededModulusSwitched / PrfMultiBitSeededModulusSwitched
// ============================================================================

pub(crate) struct PrfSeededModulusSwitched {
    mask: Vec<usize>,
    body: usize,
    log_modulus: CiphertextModulusLog,
}

impl PrfSeededModulusSwitched {
    fn zero(lwe_size: LweSize, log_modulus: CiphertextModulusLog) -> Self {
        Self {
            mask: vec![0usize; lwe_size.to_lwe_dimension().0],
            body: 0,
            log_modulus,
        }
    }

    fn fill_mask_with_random(&mut self, rng: &mut RandomGenerator<DefaultRandomGenerator>) {
        // usize is the mod switched type used during BR, but we don't have a random generation for
        // uniform usize, since the size of usize is system dependent, u32 is an ok choice as long
        // as it can contain the represented modulus.
        // log_modulus <= 32 so that 2^log_modulus fits in u32 (native modulus included).
        assert!(self.log_modulus.0 <= 32);

        for mask_element in &mut self.mask {
            *mask_element = rng.random_from_distribution_custom_mod::<u32, _>(
                Uniform,
                CiphertextModulus::new(1u128 << self.log_modulus.0),
            ) as usize;
        }
    }
}

impl ModulusSwitchedLweCiphertext<usize> for PrfSeededModulusSwitched {
    fn log_modulus(&self) -> CiphertextModulusLog {
        self.log_modulus
    }

    fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.mask.len())
    }

    fn body(&self) -> usize {
        self.body
    }

    fn mask(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.mask.iter().copied()
    }
}

pub(crate) struct PrfMultiBitSeededModulusSwitched {
    seeded_modulus_switched: PrfSeededModulusSwitched,
    grouping_factor: LweBskGroupingFactor,
}

impl PrfMultiBitSeededModulusSwitched {
    pub(crate) fn from_raw_parts(
        seeded_modulus_switched: PrfSeededModulusSwitched,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        Self {
            seeded_modulus_switched,
            grouping_factor,
        }
    }
}

impl MultiBitModulusSwitchedLweCiphertext for PrfMultiBitSeededModulusSwitched {
    fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.seeded_modulus_switched.mask.len())
    }

    fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
    }

    fn switched_modulus_input_lwe_body(&self) -> usize {
        self.seeded_modulus_switched.body
    }

    fn switched_modulus_input_mask_per_group(
        &self,
        index: usize,
    ) -> impl Iterator<Item = usize> + '_ {
        let grouping_factor = self.grouping_factor;

        let lwe_mask_elements = &self.seeded_modulus_switched.mask
            [index * grouping_factor.0..(index + 1) * grouping_factor.0];

        let modulus = 1_usize
            .checked_shl(self.seeded_modulus_switched.log_modulus.0 as u32)
            .unwrap();

        (1..grouping_factor.ggsw_per_multi_bit_element().0).map(move |power_set_index| {
            let mut monomial_degree = 0;
            for (&mask_element, selection_bit) in lwe_mask_elements
                .iter()
                .zip_eq(selection_bit(grouping_factor, power_set_index))
            {
                monomial_degree = monomial_degree
                    .wrapping_add(selection_bit.wrapping_mul(mask_element))
                    % modulus;
            }

            monomial_degree
        })
    }
}

pub(crate) struct RandomBitsRleLeBytes(Vec<u8>);

impl RandomBitsRleLeBytes {
    pub(crate) fn get(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// XOF-based seeded modulus switch (current implementation, uses OprfSeed)
// ============================================================================

/// Return the seeded inputs for each output block of the PRF, along with the Run Length Encoding
/// (RLE) byte representation of the output random bits layout. The RLE output is e.g. used in
/// [`OprfBootstrappingKey::generate_pseudo_random_bits_chunks_and_re_randomize`] to tie the
/// re-randomization seed to the same context.
///
/// `bit_chunks` is the list of per-chunk random bit counts (e.g. `[15, 15]`); each chunk
/// produces `ceil(bc / random_bits_per_block)` blocks, the last of which may be partial.
/// `random_bits_per_block` is the per-block bit budget (e.g. `2` for a 2-bit message modulus).
///
/// Returns `(seededs, rle)` where:
/// - `seededs` is the flat sequence of `(PrfSeededModulusSwitched, num_bits)` pairs representing
///   the various chunks in the same order as `bit_chunks`, with `num_bits` the random bit count
///   actually carried by a given block.
/// - `rle` is the little-endian bytes of `random_bits_per_block` plus the per-chunk  RLE layout, it
///   is used in the hash to generate the seed for the CSPRNG that produces the PRF input values.
///
/// # Panics
///
/// - if `random_bits_per_block == 0`;
/// - if `bit_chunks` contains a `0`.
pub(crate) fn create_random_from_seed_modulus_switched(
    seed: impl OprfSeed,
    lwe_size: LweSize,
    polynomial_size: PolynomialSize,
    bit_chunks: &[u64],
    random_bits_per_block: u64,
) -> (Vec<(PrfSeededModulusSwitched, u64)>, RandomBitsRleLeBytes) {
    assert_ne!(
        random_bits_per_block, 0,
        "Got random_bits_per_block == 0, this is unsupported"
    );

    assert!(
        !bit_chunks.contains(&0),
        "Got a value in bit_chunks equal to 0, this is unsupported"
    );

    // Init the hasher
    let seed_bytes = seed.into_bytes();
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(b"TFHE_PRF");
    hasher.update(seed_bytes.as_ref());

    let total_blocks: u64 = bit_chunks
        .iter()
        .map(|&bits| bits.div_ceil(random_bits_per_block))
        .sum();
    let mut seededs = Vec::with_capacity(total_blocks as usize);

    // 1 u64 to encode the random_bits_per_block, ties RLE hash and allows to distinguish similar
    // looking RLE
    //
    // and then
    //
    // Max 5 u64 per bit_chunk:
    // 1 for the total block count
    // 1 for full block count
    // 1 per bits per full block
    // 1 to encode the block count "1" for the last block
    // 1 for the number of bits in the potential last incomplete block
    let mut bit_count_rle = Vec::with_capacity(
        core::mem::size_of::<u64>() + bit_chunks.len() * 5 * core::mem::size_of::<u64>(),
    );

    bit_count_rle.extend(random_bits_per_block.to_le_bytes());

    for &bit_count in bit_chunks {
        let (num_full_blocks, last_block_bits) = (
            bit_count / random_bits_per_block,
            bit_count % random_bits_per_block,
        );

        let num_blocks = num_full_blocks + u64::from(last_block_bits != 0);
        bit_count_rle.extend(num_blocks.to_le_bytes());

        if num_full_blocks != 0 {
            bit_count_rle.extend(num_full_blocks.to_le_bytes());
            bit_count_rle.extend(random_bits_per_block.to_le_bytes());

            for _ in 0..num_full_blocks {
                seededs.push((
                    PrfSeededModulusSwitched::zero(
                        lwe_size,
                        polynomial_size.to_blind_rotation_input_modulus_log(),
                    ),
                    random_bits_per_block,
                ));
            }
        }

        if last_block_bits != 0 {
            bit_count_rle.extend(1u64.to_le_bytes());
            bit_count_rle.extend(last_block_bits.to_le_bytes());

            seededs.push((
                PrfSeededModulusSwitched::zero(
                    lwe_size,
                    polynomial_size.to_blind_rotation_input_modulus_log(),
                ),
                last_block_bits,
            ));
        }
    }

    hasher.update(&bit_count_rle);

    let xof_seed = hasher.finalize();
    let mut xof = RandomGenerator::<DefaultRandomGenerator>::new(XofSeed::new(
        xof_seed.to_vec(),
        *b"PRF_INIT",
    ));

    for (seeded, _) in &mut seededs {
        seeded.fill_mask_with_random(&mut xof);
    }

    (seededs, RandomBitsRleLeBytes(bit_count_rle))
}

// ============================================================================
// raw_seeded_msed_to_lwe (test + gpu)
// ============================================================================

#[cfg(any(test, feature = "gpu"))]
pub(crate) fn raw_seeded_msed_to_lwe<Scalar: UnsignedInteger + CastFrom<usize>>(
    seeded: &PrfSeededModulusSwitched,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> LweCiphertextOwned<Scalar> {
    let log_modulus = seeded.log_modulus();

    let container: Vec<Scalar> = seeded
        .mask()
        .chain(std::iter::once(seeded.body()))
        .map(|i| {
            let i: Scalar = i.cast_into();
            i << (Scalar::BITS - log_modulus.0)
        })
        .collect();

    LweCiphertext::from_container(container, ciphertext_modulus)
}

// ============================================================================
// generate_oprf_lut (free function, used by OprfBootstrappingKey methods)
// ============================================================================

fn generate_oprf_lut(
    random_bits: NonZeroU64,
    full_bits_count: u64,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    ciphertext_modulus: CiphertextModulus<u64>,
) -> (LookupTableOwned, Plaintext<u64>) {
    let p = 1 << random_bits.get();

    let delta = 1_u64 << (64 - full_bits_count);

    let poly_delta = 2 * polynomial_size.0 as u64 / p;

    let lut_size = LookupTableSize::new(glwe_size, polynomial_size);
    let acc = generate_lookup_table_no_encode(lut_size, ciphertext_modulus, |x| {
        (2 * (x / poly_delta) + 1) * delta / 2
    });

    let lut = LookupTableOwned {
        acc,
        degree: Degree(p - 1),
    };

    let post_pbs_constant = Plaintext(lut.degree.0 * delta / 2);

    (lut, post_pbs_constant)
}

// ============================================================================
// OPRF generation methods on OprfBootstrappingKey
// ============================================================================

impl<C: Container<Element = c64> + Sync> OprfBootstrappingKey<C> {
    /// Generates random bits split over multiple blocks, but without performing the explicit
    /// grouping of chunks in [`Vec`]s. This primitive is used to be able to re-randomize
    /// ciphertexts effectively when they are not yet grouped in chunks.
    ///
    /// For each entry `bc` in `bit_chunks`, produces a chunk of `ceil(bc /
    /// max_random_bits_per_block)` [`Ciphertext`]s, chunks are laid out consecutively in the output
    /// [`Vec`], it's the caller responsibility to collect chunks in dedicated [`Vec`]s as
    /// appropriate.
    ///
    /// Each ciphertext encrypts a value in `[0, 2^max_random_bits_per_block[`
    /// except for the last block of each chunk which may have fewer random bits: `bc=3,
    /// max_random_bits_per_block=2` -> first_block: 2 bits, last block: 1 bit.
    fn generate_pseudo_random_bits_flat(
        &self,
        seed: impl OprfSeed,
        bit_chunks: &[u64],
        max_random_bits_per_block: u64,
        target_sks: &ServerKey,
    ) -> (Vec<Ciphertext>, RandomBitsRleLeBytes) {
        let ks_key = match &target_sks.atomic_pattern {
            AtomicPatternServerKey::Standard(std) => {
                self.assert_compatible_with_target_bsk(&std.bootstrapping_key);

                match std.pbs_order {
                    PBSOrder::KeyswitchBootstrap => None,
                    PBSOrder::BootstrapKeyswitch => Some(&std.key_switching_key),
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32) => {
                self.assert_compatible_with_target_bsk(&ks32.bootstrapping_key);
                None
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Dynamic atomic pattern does not support oprf")
            }
        };

        let message_bits = target_sks.message_modulus.0.ilog2() as u64;
        let carry_bits = target_sks.carry_modulus.0.ilog2() as u64;
        let block_bit_count = 1 + message_bits + carry_bits;
        assert!(
            max_random_bits_per_block <= block_bit_count,
            "The requested max_random_bits_per_block (={max_random_bits_per_block}) \
            does not fit in a block. A maximum of {block_bit_count} bits can fit in a single block."
        );

        let polynomial_size = self.polynomial_size();
        let in_lwe_size = self.input_lwe_dimension().to_lwe_size();

        let (seeded_cts, random_bits_rle) = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            polynomial_size,
            bit_chunks,
            max_random_bits_per_block,
        );

        let ciphertext_modulus = target_sks.ciphertext_modulus;
        let max_bits = seeded_cts.iter().map(|(_, b)| *b).max().unwrap_or(0);
        // 1..=max_bits are positive, filter_map avoids unwrapping on an infallible new call
        let luts = (1..=max_bits)
            .filter_map(NonZeroU64::new)
            .map(|bit| {
                generate_oprf_lut(
                    bit,
                    block_bit_count,
                    polynomial_size,
                    self.glwe_size(),
                    ciphertext_modulus,
                )
            })
            .collect::<Vec<_>>();

        let flat: Vec<Ciphertext> = seeded_cts
            .into_par_iter()
            .map(|(seeded, num_bits)| {
                let (LookupTableOwned { mut acc, degree }, post_pbs_constant) =
                    luts[num_bits as usize - 1].clone();

                match self {
                    Self::Classic { bsk, .. } => {
                        ShortintEngine::with_thread_local_mut(|engine| {
                            let buffers = engine.get_computation_buffers();

                            apply_standard_blind_rotate(bsk, &seeded, &mut acc, buffers);
                        });
                    }
                    Self::MultiBit {
                        fourier_bsk,
                        thread_count,
                        deterministic_execution,
                    } => {
                        let seeded_multi_bit = PrfMultiBitSeededModulusSwitched::from_raw_parts(
                            seeded,
                            fourier_bsk.grouping_factor(),
                        );

                        apply_multi_bit_blind_rotate(
                            &seeded_multi_bit,
                            &mut acc,
                            fourier_bsk,
                            *thread_count,
                            *deterministic_execution,
                        );
                    }
                }

                let mut pbs_output = LweCiphertext::new(
                    0u64,
                    self.output_lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );
                extract_lwe_sample_from_glwe_ciphertext(&acc, &mut pbs_output, MonomialDegree(0));
                lwe_ciphertext_plaintext_add_assign(&mut pbs_output, post_pbs_constant);

                let final_lwe = if let Some(ks_key) = ks_key {
                    let mut ct_ksed = LweCiphertext::new(
                        0,
                        ks_key.output_key_lwe_dimension().to_lwe_size(),
                        ks_key.ciphertext_modulus(),
                    );

                    keyswitch_lwe_ciphertext(ks_key, &pbs_output, &mut ct_ksed);
                    ct_ksed
                } else {
                    pbs_output
                };

                Ciphertext::new(
                    final_lwe,
                    degree,
                    NoiseLevel::NOMINAL,
                    target_sks.message_modulus,
                    target_sks.carry_modulus,
                    target_sks.atomic_pattern.kind(),
                )
            })
            .collect();

        (flat, random_bits_rle)
    }

    /// Generates random bits split over multiple blocks, grouped per input chunk.
    ///
    /// For each entry `bc` in `bit_chunks`, produces a `Vec<Ciphertext>` of
    /// `ceil(bc / max_random_bits_per_block)` blocks. Each ciphertext encrypts a value in
    /// `[0, 2^max_random_bits_per_block[` except for the last block of each chunk which may have
    /// fewer random bits: `bc=3, max_random_bits_per_block=2` -> first_block: 2 bits, last
    /// block: 1 bit.
    pub(crate) fn generate_pseudo_random_bits_chunks(
        &self,
        seed: impl OprfSeed,
        bit_chunks: &[u64],
        max_random_bits_per_block: u64,
        target_sks: &ServerKey,
    ) -> Vec<Vec<Ciphertext>> {
        let (flat, _rle_info) = self.generate_pseudo_random_bits_flat(
            seed,
            bit_chunks,
            max_random_bits_per_block,
            target_sks,
        );

        let mut iter = flat.into_iter();
        bit_chunks
            .iter()
            .map(|&bc| {
                let n = bc.div_ceil(max_random_bits_per_block) as usize;
                iter.by_ref().take(n).collect()
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generate_pseudo_random_bits_chunks_and_re_randomize(
        &self,
        prf_seed: impl OprfSeed,
        bit_chunks: &[u64],
        random_bits_per_block: u64,
        target_sks: &ServerKey,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: Option<&KeySwitchingKeyMaterialView>,
        rerand_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<Vec<Vec<Ciphertext>>> {
        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let (mut flat_result, random_bits_rle) = self.generate_pseudo_random_bits_flat(
            prf_seed,
            bit_chunks,
            random_bits_per_block,
            target_sks,
        );

        let rerand_seed =
            ReRandomizationSeed::new_prf_rerand_seed(rerand_hash_algo, prf_seed, &random_bits_rle);

        compact_public_key.re_randomize_ciphertexts(
            &mut flat_result,
            key_switching_key_material,
            rerand_seed,
        )?;

        let mut iter = flat_result.into_iter();
        Ok(bit_chunks
            .iter()
            .map(|&bc| {
                let n = bc.div_ceil(random_bits_per_block) as usize;
                iter.by_ref().take(n).collect()
            })
            .collect())
    }
}

// Made public to help KMS check their results and avoid code duplication
pub mod test_utils {
    /// Takes as input a cleartext (for tests you should decrypt the PRF input to get the cleartext
    /// that would be fed into the encrypted PRF) and returns the expected PRF result for it.
    ///
    /// input_cleartext: cleartext decrypted from the PRF input
    /// random_bits_count: how many random bits should the PRF output, for example even if you have
    /// a total cleartext space of 4 bits, you may want to keep the top two bits (carry bits) equal
    /// to 0 to keep the carry free.
    /// output_modulus: the output cleartext space, continuing the above example, it must contain
    /// the padding bit, so for 4 bits of cleartext this is actually 2^(1 + 4)==32
    pub fn cleartext_prf(
        input_cleartext: u64,
        random_bits_count: u64,
        output_modulus: u64,
        prf_polynomial_size: u64,
    ) -> u64 {
        let input_modulus = 2 * prf_polynomial_size;
        let random_value_modulus = 1 << random_bits_count;
        let poly_delta = 2 * prf_polynomial_size / random_value_modulus;

        let half_negacyclic_part = |x| 2 * (x / poly_delta) + 1;
        let negacyclic_part = |x| {
            assert!(x < input_modulus);
            if x < input_modulus / 2 {
                half_negacyclic_part(x)
            } else {
                2 * output_modulus - half_negacyclic_part(x - (input_modulus / 2))
            }
        };

        let a: u64 =
            (negacyclic_part(input_cleartext) + random_value_modulus - 1) % (2 * output_modulus);
        assert!(a.is_multiple_of(2));
        a / 2
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
pub(crate) mod test {
    use super::test_utils::cleartext_prf;
    use super::*;
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::prelude::{
        decrypt_lwe_ciphertext, new_seeder, CastInto, LweSecretKeyView,
    };
    use crate::shortint::oprf::create_random_from_seed_modulus_switched;
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    };
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use crate::shortint::{gen_keys, ClientKey, ServerKey, ShortintParameterSet};
    use rand::SeedableRng;
    use statrs::distribution::ContinuousCDF;
    use std::collections::HashMap;

    fn square(a: f64) -> f64 {
        a * a
    }

    struct PlainPrfResult {
        seed: Seed,
        output: u64,
        expected_output: u64,
    }

    #[test]
    fn oprf_compare_plain_ci_run_filter() {
        for params in [
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let (ck, sk) = gen_keys(params);
            let oprf_ck = OprfPrivateKey::new(&ck);
            let oprf_sk = OprfServerKey::new(&oprf_ck, &ck).unwrap();

            let results: Vec<_> = (0..1000)
                .into_par_iter()
                .map(|seed| oprf_compare_plain_from_seed(Seed(seed), &ck, &oprf_ck, &oprf_sk, &sk))
                .collect();

            let mut all_ok = true;
            for res in results {
                if let Err(PlainPrfResult {
                    seed,
                    output,
                    expected_output,
                }) = res
                {
                    all_ok = false;

                    println!(
                        "Error with seed {seed:?}, got output={output}, expected={expected_output}"
                    );
                }
            }

            assert!(all_ok, "Test failed, see above log");
        }
    }

    fn oprf_compare_plain_from_seed(
        seed: Seed,
        ck: &ClientKey,
        oprf_ck: &OprfPrivateKey,
        oprf_sk: &OprfServerKey,
        sk: &ServerKey,
    ) -> Result<(), PlainPrfResult> {
        let params = ck.parameters();

        let random_bits_count = params.message_modulus().0.ilog2().into();

        let img = oprf_sk
            .generate_oblivious_pseudo_random_bits_chunks(seed, &[random_bits_count], sk)
            .into_iter()
            .next()
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let plain_prf_input = match &oprf_ck.0 {
            AtomicPatternOprfPrivateKey::Standard(sk) => gen_prf_input(&sk.as_view(), seed, params),
            AtomicPatternOprfPrivateKey::KeySwitch32(sk) => {
                gen_prf_input(&sk.as_view(), seed, params)
            }
        };

        // includes padding bit
        let output_modulus = 2 * params.message_modulus().0 * params.carry_modulus().0;
        let expected_output = cleartext_prf(
            plain_prf_input,
            random_bits_count,
            output_modulus,
            params.polynomial_size().0 as u64,
        );
        let output = ck.decrypt_message_and_carry(&img);

        let output_random_value_modulus = 1 << random_bits_count;

        let output_range_ok = output < output_random_value_modulus;
        let output_is_expected_value = output == expected_output;

        let result_is_ok = output_range_ok && output_is_expected_value;

        if result_is_ok {
            Ok(())
        } else {
            Err(PlainPrfResult {
                seed,
                output,
                expected_output,
            })
        }
    }

    /// Returns the value used as input of the pbs for the prf with the provided seed
    fn gen_prf_input<Scalar>(
        sk: &LweSecretKeyView<Scalar>,
        seed: Seed,
        params: ShortintParameterSet,
    ) -> u64
    where
        Scalar: UnsignedInteger + CastFrom<usize> + CastInto<u64> + CastInto<usize>,
    {
        let lwe_size = params.lwe_dimension().to_lwe_size();
        let input_p = 2 * params.polynomial_size().0 as u64;
        let log_input_p = input_p.ilog2() as usize;

        let ciphertext_modulus = CiphertextModulus::new_native();
        let message_bits = params.message_modulus().0.ilog2() as u64;

        let (seeded_chunks, _rle_info) = create_random_from_seed_modulus_switched(
            seed,
            lwe_size,
            params.polynomial_size(),
            &[message_bits],
            message_bits,
        );

        assert_eq!(seeded_chunks.len(), 1);

        let seeded = &seeded_chunks[0].0;

        assert!(seeded.mask.iter().all(|v| *v < input_p as usize));

        let ct = raw_seeded_msed_to_lwe(seeded, ciphertext_modulus);

        CastInto::<u64>::cast_into(
            decrypt_lwe_ciphertext(sk, &ct)
                .0
                .wrapping_add(Scalar::ONE << (Scalar::BITS - log_input_p - 1))
                >> (Scalar::BITS - log_input_p),
        )
    }

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 100_000;

        let p_value_limit: f64 = 0.000_01;

        for params in [
            ShortintParameterSet::from(
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            ),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let (ck, sk) = gen_keys(params);
            let oprf_ck = OprfPrivateKey::new(&ck);
            let oprf_sk = OprfServerKey::new(&oprf_ck, &ck).unwrap();

            let test_uniformity = |distinct_values: u64, f: &(dyn Fn(usize) -> u64 + Sync)| {
                test_uniformity(sample_count, p_value_limit, distinct_values, f)
            };

            let random_bits_count = 2;

            test_uniformity(1 << random_bits_count, &|seed| {
                let img = oprf_sk.generate_oblivious_pseudo_random_bits_chunks(
                    Seed(seed as u128),
                    &[random_bits_count],
                    &sk,
                );

                assert_eq!(img.len(), 1);
                assert_eq!(img[0].len(), 1);

                ck.decrypt_message_and_carry(&img[0][0])
            });
        }
    }

    pub(crate) fn test_uniformity<F>(
        sample_count: usize,
        p_value_limit: f64,
        distinct_values: u64,
        f: F,
    ) where
        F: Sync + Fn(usize) -> u64,
    {
        let p_value = uniformity_p_value(f, sample_count, distinct_values);

        assert!(
            p_value_limit < p_value,
            "p_value (={p_value}) expected to be bigger than {p_value_limit}"
        );
    }

    pub(crate) fn uniformity_p_value<F>(f: F, sample_count: usize, distinct_values: u64) -> f64
    where
        F: Sync + Fn(usize) -> u64,
    {
        let values: Vec<_> = (0..sample_count).into_par_iter().map(&f).collect();

        let mut values_count = HashMap::new();

        for i in values.iter().copied() {
            assert!(
                i < distinct_values,
                "i (={i}) is supposed to be smaller than distinct_values (={distinct_values})",
            );

            *values_count.entry(i).or_insert(0) += 1;
        }

        let single_expected_count = sample_count as f64 / distinct_values as f64;

        // https://en.wikipedia.org/wiki/Pearson's_chi-squared_test
        let distance: f64 = (0..distinct_values)
            .map(|value| *values_count.get(&value).unwrap_or(&0))
            .map(|count| square(count as f64 - single_expected_count) / single_expected_count)
            .sum();

        statrs::distribution::ChiSquared::new((distinct_values - 1) as f64)
            .unwrap()
            .sf(distance)
    }

    fn bits_in_block(
        block_index: usize,
        num_blocks: usize,
        random_bits_count: u64,
        random_bits_per_block: u64,
    ) -> u64 {
        if block_index == num_blocks - 1 {
            let last = random_bits_count % random_bits_per_block;
            if last == 0 {
                random_bits_per_block
            } else {
                last
            }
        } else {
            random_bits_per_block
        }
    }

    #[test]
    #[should_panic(expected = "Got a value in bit_chunks equal to 0, this is unsupported")]
    // Zero bit OPRF is not mathematically well defined
    fn oprf_zero_bit_panics() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let oprf_ck = OprfPrivateKey::new(&ck);
        let oprf_sk = OprfServerKey::new(&oprf_ck, &ck).unwrap();

        let _ = oprf_sk.generate_oblivious_pseudo_random_bits_chunks(Seed(0), &[0], &sk);
    }

    #[test]
    fn oprf_test_blocks_range_bits_ci_run_filter() {
        let mut seeder = new_seeder();
        let rng_seed: [u8; 32] = std::array::from_fn(|_| seeder.seed().0 as u8);
        println!("oprf_test_blocks_range_bits rng_seed: {rng_seed:?}");

        for params in [
            ShortintParameterSet::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let (ck, sk) = gen_keys(params);
            let oprf_ck = OprfPrivateKey::new(&ck);
            let oprf_sk = OprfServerKey::new(&oprf_ck, &ck).unwrap();

            let random_bits_per_block = sk.message_modulus.0.ilog2() as u64;

            for random_bits_count in [
                1,
                random_bits_per_block,
                random_bits_per_block + 1,
                2 * random_bits_per_block,
                (2 * random_bits_per_block) + 1,
            ] {
                let expected_num_blocks =
                    random_bits_count.div_ceil(random_bits_per_block) as usize;

                let mut rng = rand::rngs::StdRng::from_seed(rng_seed);

                for _ in 0..50 {
                    let seed_val: u128 = rand::Rng::gen(&mut rng);
                    let blocks = oprf_sk.generate_oblivious_pseudo_random_bits_chunks(
                        Seed(seed_val),
                        &[random_bits_count],
                        &sk,
                    );

                    assert_eq!(blocks.len(), 1);
                    let blocks = blocks.into_iter().next().unwrap();
                    assert_eq!(blocks.len(), expected_num_blocks);

                    for (i, block) in blocks.iter().enumerate() {
                        let decrypted = ck.decrypt_message_and_carry(block);
                        let block_bits = bits_in_block(
                            i,
                            expected_num_blocks,
                            random_bits_count,
                            random_bits_per_block,
                        );
                        assert!(
                            decrypted < (1 << block_bits),
                            "block {i}: decrypted value {decrypted} >= {}",
                            1u64 << block_bits,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn prf_rle_encoding() {
        let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        let lwe_size = params.lwe_dimension.to_lwe_size();
        let polynomial_size = params.polynomial_size;

        let (a, rle_a) =
            create_random_from_seed_modulus_switched(Seed(0), lwe_size, polynomial_size, &[1], 2);
        let (b, rle_b) =
            create_random_from_seed_modulus_switched(Seed(0), lwe_size, polynomial_size, &[1], 4);
        // Different bits (2 vs. 4) should produce different RLE even when all blocks encoding are
        // the same
        assert_ne!(rle_a.0, rle_b.0);
        // Check the generated bytes are indeed different too
        assert_ne!(&a[0].0.mask, &b[0].0.mask);

        for (index, (input, bits_per_block, expected)) in [
            (vec![1, 1], 2, vec![2u64, 1, 1, 1, 1, 1, 1]),
            (vec![1, 1], 4, vec![4, 1, 1, 1, 1, 1, 1]),
            (vec![15, 15], 2, vec![2, 8, 7, 2, 1, 1, 8, 7, 2, 1, 1]),
            (
                vec![14, 1, 14, 1],
                2,
                vec![2, 7, 7, 2, 1, 1, 1, 7, 7, 2, 1, 1, 1],
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let (_, rle) = create_random_from_seed_modulus_switched(
                Seed(0),
                lwe_size,
                polynomial_size,
                &input,
                bits_per_block,
            );

            let expected_rle: Vec<_> = expected.into_iter().flat_map(|x| x.to_le_bytes()).collect();
            assert_eq!(rle.get(), &expected_rle, "Error at input #{index}");
        }
    }

    #[test]
    fn prf_with_re_randomization() {
        use crate::shortint::CompactPrivateKey;
        use rand::prelude::*;

        let mut rng = rand::thread_rng();

        for params in [
            ShortintParameterSet::from(
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            ),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let message_bits: u64 = params.message_modulus().0.ilog2().into();

            let (cks, sks) = gen_keys(params);

            // No KS rerand
            let privk: CompactPrivateKey<&[u64]> = (&cks).try_into().unwrap();
            let pubk = CompactPublicKey::new(&privk);
            // PRF key
            let oprf_cks = OprfPrivateKey::new(&cks);
            let oprf_sks = OprfServerKey::new(&oprf_cks, &cks).unwrap();

            let prf_seed: [u8; 256 / 8] = core::array::from_fn(|_| rng.gen());
            let bit_chunks: Vec<u64> = (0..10).map(|_| rng.gen_range(1..=64)).collect();

            println!("prf_seed={prf_seed:?}");
            println!("bit_chunks={bit_chunks:?}");

            let prf_not_rerand_chunks = oprf_sks.generate_oblivious_pseudo_random_bits_chunks(
                prf_seed.as_ref(),
                &bit_chunks,
                &sks,
            );

            for rerand_hash_algo in [
                ReRandomizationHashAlgo::Blake3,
                ReRandomizationHashAlgo::Shake256,
            ] {
                let prf_rerand_chunks = oprf_sks
                    .generate_oblivious_pseudo_random_bits_chunks_and_re_randomize(
                        prf_seed.as_ref(),
                        &bit_chunks,
                        &sks,
                        &pubk,
                        None,
                        rerand_hash_algo,
                    )
                    .unwrap();

                assert_eq!(prf_not_rerand_chunks.len(), bit_chunks.len());
                assert_eq!(prf_rerand_chunks.len(), bit_chunks.len());

                for (requested_rand_bits, (prf, prf_rerand)) in bit_chunks
                    .iter()
                    .zip(prf_not_rerand_chunks.iter().zip(prf_rerand_chunks.iter()))
                {
                    let expected_len: usize = requested_rand_bits
                        .div_ceil(message_bits)
                        .try_into()
                        .unwrap();
                    assert_eq!(prf.len(), expected_len);
                    assert_eq!(prf_rerand.len(), expected_len);

                    for (block_idx, (prf_ct, prf_rerand_ct)) in
                        prf.iter().zip(prf_rerand.iter()).enumerate()
                    {
                        let is_last_block = block_idx == expected_len - 1;
                        let expected_max_value = if is_last_block {
                            let last_block_is_full =
                                requested_rand_bits.is_multiple_of(message_bits);
                            if last_block_is_full {
                                1 << message_bits
                            } else {
                                let remaining_bits = requested_rand_bits % message_bits;
                                1 << remaining_bits
                            }
                        } else {
                            1 << message_bits
                        };

                        let Ciphertext {
                            ct: prf_lwe,
                            degree: prf_degree,
                            message_modulus: prf_message_modulus,
                            carry_modulus: prf_carry_modulus,
                            atomic_pattern: prf_atomic_pattern,
                            .. // NoiseLevel private on purpose to avoid manual modifications
                        } = prf_ct;
                        let prf_noise_level = prf_ct.noise_level();

                        let Ciphertext {
                            ct: prf_rerand_lwe,
                            degree: prf_rerand_degree,
                            message_modulus: prf_rerand_message_modulus,
                            carry_modulus: prf_rerand_carry_modulus,
                            atomic_pattern: prf_rerand_atomic_pattern,
                            .. // NoiseLevel private on purpose to avoid manual modifications
                        } = prf_rerand_ct;
                        let prf_rerand_noise_level = prf_rerand_ct.noise_level();

                        assert_ne!(prf_lwe, prf_rerand_lwe);
                        assert_eq!(prf_degree, prf_rerand_degree);
                        // Check expected max degree
                        assert_eq!(prf_degree.0, expected_max_value - 1);
                        assert_eq!(prf_message_modulus, prf_rerand_message_modulus);
                        assert_eq!(prf_carry_modulus, prf_rerand_carry_modulus);
                        assert_eq!(prf_atomic_pattern, prf_rerand_atomic_pattern);
                        assert_eq!(prf_noise_level, prf_rerand_noise_level);

                        assert_eq!(prf_noise_level, NoiseLevel::NOMINAL);

                        let prf_dec = cks.decrypt_message_and_carry(prf_ct);
                        assert!(prf_dec < expected_max_value, "invalid PRF output range");

                        let prf_rerand_dec = cks.decrypt_message_and_carry(prf_rerand_ct);
                        assert_eq!(
                            prf_dec, prf_rerand_dec,
                            "rerand PRF differs from non-rerand PRF"
                        );
                    }
                }
            }
        }
    }
}
