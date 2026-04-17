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
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{KeySwitch32PBSParameters, NoiseLevel};
use crate::shortint::server_key::{
    apply_multi_bit_blind_rotate, apply_standard_blind_rotate, generate_lookup_table_no_encode,
    LookupTableOwned, PBSConformanceParams, PbsTypeConformanceParams, ShortintBootstrappingKey,
};
use crate::shortint::{AtomicPatternParameters, ClientKey, PBSParameters, ServerKey};
use aligned_vec::ABox;
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
    KeySwitch32(LweSecretKeyOwned<u32>),
    Standard(LweSecretKeyOwned<u64>),
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
    /// Uniformly generates a random encrypted ciphertexts
    ///
    ///
    /// Generates `bit_count` random bits split over multiple blocks
    ///
    /// Each ciphertexts encrypt a value in `[0, 2^random_bits_per_block[`
    /// except for the last one which may have less random bits:
    /// `bit_count=3, random_bits_per_block=2` -> first_block: 2 bits, last blocks: 1 bit
    ///
    ///
    /// # Panics
    ///
    /// * Panics if `randim_bits_per_blocks` is greater than the total number of bits in a block
    /// * Panics if `self` is not compatible with `target_sks`
    pub fn generate_oblivious_pseudo_random_bits(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Vec<Ciphertext> {
        self.inner.generate_pseudo_random_bits(
            seed,
            random_bits_count,
            target_sks.message_modulus.0.ilog2() as u64,
            target_sks,
        )
    }

    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    ///
    /// `2^random_bits_count` must be smaller than the message modulus
    ///
    /// The encrypted value is oblivious to the server
    pub fn generate_oblivious_pseudo_random(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext {
        self.inner
            .generate_oblivious_pseudo_random(seed, random_bits_count, target_sks)
    }

    /// Uniformly generates a random value in `[0, 2^random_bits_count[`
    ///
    /// `2^random_bits_count` must be smaller than the message_modulus*carry_modulus
    ///
    /// The encrypted value is oblivious to the server
    pub fn generate_oblivious_pseudo_random_message_and_carry(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext {
        self.inner
            .generate_oblivious_pseudo_random_message_and_carry(seed, random_bits_count, target_sks)
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

// ============================================================================
// XOF-based seeded modulus switch (current implementation, uses OprfSeed)
// ============================================================================

pub(crate) fn create_random_from_seed_modulus_switched(
    seed: impl OprfSeed,
    lwe_size: LweSize,
    polynomial_size: PolynomialSize,
    count: LweCiphertextCount,
) -> Vec<PrfSeededModulusSwitched> {
    let bytes = seed.into_bytes();
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(b"TFHE_PRF");
    hasher.update(bytes.as_ref());
    let seed = hasher.finalize();

    let mut xof =
        RandomGenerator::<DefaultRandomGenerator>::new(XofSeed::new(seed.to_vec(), *b"PRF_INIT"));

    (0..count.0)
        .map(|_| {
            let mut mask = vec![0usize; lwe_size.to_lwe_dimension().0];
            for mask_element in &mut mask {
                *mask_element = xof.random_from_distribution_custom_mod::<u32, _>(
                    Uniform,
                    CiphertextModulus::new(2 * polynomial_size.0 as u128),
                ) as usize;
            }
            PrfSeededModulusSwitched {
                mask,
                body: 0,
                log_modulus: polynomial_size.to_blind_rotation_input_modulus_log(),
            }
        })
        .collect::<Vec<_>>()
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
    random_bits: u64,
    full_bits_count: u64,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    ciphertext_modulus: CiphertextModulus<u64>,
) -> (LookupTableOwned, Plaintext<u64>) {
    let p = 1 << random_bits;

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
    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    /// `2^random_bits_count` must be smaller than the message modulus
    /// The encrypted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext {
        assert!(
            random_bits_count < 64,
            "random_bits_count >= 64 is not supported",
        );
        assert!(
            1 << random_bits_count <= target_sks.message_modulus.0,
            "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [0, {}[",
            random_bits_count, target_sks.message_modulus.0
        );

        let mut blocks = self.generate_pseudo_random_bits(
            seed,
            random_bits_count,
            random_bits_count, // This means we will have one block
            target_sks,
        );
        assert_eq!(blocks.len(), 1);
        blocks.pop().unwrap()
    }

    /// Uniformly generates a random value in `[0, 2^random_bits_count[`
    /// The encrypted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random_message_and_carry(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext {
        assert!(
            target_sks.message_modulus.0.is_power_of_two(),
            "The message modulus(={}), must be a power of 2 to use the OPRF",
            target_sks.message_modulus.0
        );
        let message_bits_count = target_sks.message_modulus.0.ilog2() as u64;

        assert!(
            target_sks.carry_modulus.0.is_power_of_two(),
            "The carry modulus(={}), must be a power of 2 to use the OPRF",
            target_sks.carry_modulus.0
        );
        let carry_bits_count = target_sks.carry_modulus.0.ilog2() as u64;

        assert!(
            random_bits_count <= carry_bits_count + message_bits_count,
            "The number of random bits asked for (={random_bits_count}) is bigger than carry_bits_count (={carry_bits_count}) + message_bits_count(={message_bits_count})",
        );

        let mut blocks = self.generate_pseudo_random_bits(
            seed,
            random_bits_count,
            random_bits_count, // This means we will have one block
            target_sks,
        );
        assert_eq!(blocks.len(), 1);
        blocks.pop().unwrap()
    }

    /// Generates `bit_count` random bits split over multiple blocks.
    ///
    /// Each ciphertext encrypts a value in `[0, 2^random_bits_per_block[`
    /// except for the last one which may have fewer random bits:
    /// `bit_count=3, random_bits_per_block=2` -> first_block: 2 bits, last block: 1 bit
    pub(crate) fn generate_pseudo_random_bits(
        &self,
        seed: impl OprfSeed,
        bit_count: u64,
        random_bits_per_block: u64,
        target_sks: &ServerKey,
    ) -> Vec<Ciphertext> {
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
        let bits_in_one_block = 1 + message_bits + carry_bits;
        assert!(
            random_bits_per_block <= bits_in_one_block,
            "The number of random bits asked for (={random_bits_per_block}) is bigger than full_bits_count (={bits_in_one_block})"
        );

        let polynomial_size = self.polynomial_size();
        let in_lwe_size = self.input_lwe_dimension().to_lwe_size();
        let num_blocks = bit_count.div_ceil(random_bits_per_block) as usize;

        let seeded_cts = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            polynomial_size,
            LweCiphertextCount(num_blocks),
        );

        let ciphertext_modulus = target_sks.ciphertext_modulus;
        let last_block_bits = bit_count % random_bits_per_block;

        let regular_lut = generate_oprf_lut(
            random_bits_per_block,
            bits_in_one_block,
            polynomial_size,
            self.glwe_size(),
            ciphertext_modulus,
        );
        let last_block_lut = if last_block_bits != 0 {
            Some(generate_oprf_lut(
                last_block_bits,
                bits_in_one_block,
                polynomial_size,
                self.glwe_size(),
                ciphertext_modulus,
            ))
        } else {
            None
        };

        seeded_cts
            .into_par_iter()
            .enumerate()
            .map(|(i, seeded)| {
                let (LookupTableOwned { mut acc, degree }, post_pbs_constant) =
                    if i == num_blocks - 1 && last_block_lut.is_some() {
                        last_block_lut.clone().unwrap()
                    } else {
                        regular_lut.clone()
                    };

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
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::prelude::{decrypt_lwe_ciphertext, CastInto, LweSecretKeyView};
    use crate::shortint::oprf::create_random_from_seed_modulus_switched;
    use crate::shortint::{ClientKey, ServerKey, ShortintParameterSet};
    use rand::SeedableRng;
    use statrs::distribution::ContinuousCDF;
    use std::collections::HashMap;

    fn square(a: f64) -> f64 {
        a * a
    }

    #[test]
    fn oprf_compare_plain_ci_run_filter() {
        use crate::shortint::gen_keys;
        use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        for params in [
            ShortintParameterSet::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let (ck, sk) = gen_keys(params);
            let oprf_ck = OprfPrivateKey::new(&ck);
            let oprf_sk = OprfServerKey::new(&oprf_ck, &ck).unwrap();

            for seed in 0..1000u128 {
                oprf_compare_plain_from_seed(Seed(seed), &ck, &oprf_ck, &oprf_sk, &sk);
            }
        }
    }

    fn oprf_compare_plain_from_seed(
        seed: Seed,
        ck: &ClientKey,
        oprf_ck: &OprfPrivateKey,
        oprf_sk: &OprfServerKey,
        sk: &ServerKey,
    ) {
        let params = ck.parameters();

        let random_bits_count = 2;

        let input_p = 2 * params.polynomial_size().0 as u64;

        let p_prime = 1 << random_bits_count;

        let output_p = 2 * params.carry_modulus().0 * params.message_modulus().0;

        let poly_delta = 2 * params.polynomial_size().0 as u64 / p_prime;

        let img = oprf_sk.generate_oblivious_pseudo_random(seed, random_bits_count, sk);

        let plain_prf_input = match &oprf_ck.0 {
            AtomicPatternOprfPrivateKey::Standard(sk) => gen_prf_input(&sk.as_view(), seed, params),
            AtomicPatternOprfPrivateKey::KeySwitch32(sk) => {
                gen_prf_input(&sk.as_view(), seed, params)
            }
        };

        let half_negacyclic_part = |x| 2 * (x / poly_delta) + 1;

        let negacyclic_part = |x| {
            assert!(x < input_p);
            if x < input_p / 2 {
                half_negacyclic_part(x)
            } else {
                2 * output_p - half_negacyclic_part(x - (input_p / 2))
            }
        };

        let prf = |x| {
            let a: u64 = (negacyclic_part(x) + p_prime - 1) % (2 * output_p);
            assert!(a.is_multiple_of(2));
            a / 2
        };

        let expected_output = prf(plain_prf_input);
        let output = ck.decrypt_message_and_carry(&img);

        assert!(output < p_prime);
        assert_eq!(output, expected_output);
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

        let seeded = create_random_from_seed_modulus_switched(
            seed,
            lwe_size,
            params.polynomial_size(),
            LweCiphertextCount(1),
        )
        .pop()
        .unwrap();

        let ct = raw_seeded_msed_to_lwe(&seeded, ciphertext_modulus);

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

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::test_params::{
            TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        };
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        for params in [
            ShortintParameterSet::from(
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            ),
            ShortintParameterSet::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS),
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
                let img = oprf_sk.generate_oblivious_pseudo_random(
                    Seed(seed as u128),
                    random_bits_count,
                    &sk,
                );

                ck.decrypt_message_and_carry(&img)
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
    fn oprf_test_blocks_range_bits_ci_run_filter() {
        use crate::core_crypto::prelude::new_seeder;
        use crate::shortint::gen_keys;
        use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

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
            let blocks = oprf_sk.generate_oblivious_pseudo_random_bits(Seed(0), 0, &sk);
            assert!(blocks.is_empty());

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
                    let blocks = oprf_sk.generate_oblivious_pseudo_random_bits(
                        Seed(seed_val),
                        random_bits_count,
                        &sk,
                    );

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
    fn oprf_test_uniformity_bits_ci_run_filter() {
        let sample_count: usize = 100_000;

        let p_value_limit: f64 = 0.000_01;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::test_params::{
            TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        };
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        for params in [
            ShortintParameterSet::from(
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            ),
            ShortintParameterSet::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let (ck, sk) = gen_keys(params);
            let oprf_ck = OprfPrivateKey::new(&ck);
            let oprf_sk = OprfServerKey::new(&oprf_ck, &ck).unwrap();

            let random_bits_per_block = sk.message_modulus.0.ilog2() as u64;

            for random_bits_count in [3u64, 4] {
                let expected_num_blocks =
                    random_bits_count.div_ceil(random_bits_per_block) as usize;

                test_uniformity(
                    sample_count,
                    p_value_limit,
                    1 << random_bits_count,
                    |seed| {
                        let seed = (seed as u128).to_le_bytes();
                        let blocks = oprf_sk.generate_oblivious_pseudo_random_bits(
                            seed.as_slice(),
                            random_bits_count,
                            &sk,
                        );

                        let mut combined: u64 = 0;
                        let mut shift = 0u64;
                        for (i, block) in blocks.iter().enumerate() {
                            let decrypted = ck.decrypt_message_and_carry(block);
                            let block_bits = bits_in_block(
                                i,
                                expected_num_blocks,
                                random_bits_count,
                                random_bits_per_block,
                            );
                            combined |= decrypted << shift;
                            shift += block_bits;
                        }

                        combined
                    },
                );
            }
        }
    }
}
