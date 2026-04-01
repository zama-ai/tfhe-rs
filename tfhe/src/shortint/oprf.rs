use tfhe_versionable::Versionize;

use super::backward_compatibility::oprf::*;
use super::client_key::atomic_pattern::AtomicPatternClientKey;
use super::server_key::LookupTableSize;
use super::Ciphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::*;
use crate::shortint::atomic_pattern::{AtomicPattern, AtomicPatternServerKey};
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{KeySwitch32PBSParameters, NoiseLevel};
use crate::shortint::server_key::{
    apply_multi_bit_blind_rotate, apply_standard_blind_rotate, generate_lookup_table_no_encode,
    PBSConformanceParams, PbsTypeConformanceParams,
};
use crate::shortint::{AtomicPatternParameters, ClientKey, PBSParameters, ServerKey};
use aligned_vec::ABox;
use itertools::Itertools;
use tfhe_csprng::seeders::Seed;
use tfhe_fft::c64;

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
    pub(crate) fn to_fourier(&self) -> OprfBootstrappingKeyOwned {
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

#[derive(PartialEq, Eq)]
pub enum ExpandedOprfServerKey {
    Standard(ExpandedOprfBootstrappingKey),
    KeySwitch32(ExpandedOprfBootstrappingKey),
}

impl ExpandedOprfServerKey {
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_fourier(self) -> OprfServerKey {
        match self {
            Self::Standard(std) => OprfServerKey::from_raw_parts(
                AtomicPatternOprfServerKey::Standard(std.to_fourier()),
            ),
            Self::KeySwitch32(ks32) => OprfServerKey::from_raw_parts(
                AtomicPatternOprfServerKey::KeySwitch32(ks32.to_fourier()),
            ),
        }
    }
}

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

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedAtomicPatternOprfServerKeyVersions)]
pub enum CompressedAtomicPatternOprfServerKey {
    KeySwitch32(CompressedOprfBootstrappingKey),
    Standard(CompressedOprfBootstrappingKey),
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedOprfServerKeyVersions)]
pub struct CompressedOprfServerKey {
    pub(crate) inner: CompressedAtomicPatternOprfServerKey,
}

impl CompressedOprfServerKey {
    pub fn new(sk: &OprfPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        let key = match (&sk.0, &target_ck.atomic_pattern) {
            (
                AtomicPatternOprfPrivateKey::KeySwitch32(sk),
                AtomicPatternClientKey::KeySwitch32(ck),
            ) => ShortintEngine::with_thread_local_mut(|engine| {
                let bsk = engine.new_compressed_oprf_bootstrapping_key_ks32(
                    ck.parameters,
                    sk,
                    &ck.glwe_secret_key,
                );

                CompressedAtomicPatternOprfServerKey::KeySwitch32(bsk)
            }),
            (AtomicPatternOprfPrivateKey::Standard(sk), AtomicPatternClientKey::Standard(ck)) => {
                let bsk = ShortintEngine::with_thread_local_mut(|engine| {
                    engine.new_compressed_oprf_bootstrapping_key_standard(
                        ck.parameters,
                        sk,
                        &ck.glwe_secret_key,
                    )
                });
                CompressedAtomicPatternOprfServerKey::Standard(bsk)
            }
            _ => {
                return Err(crate::error!(
                    "Mismatched atomic_patterns for oprf key and client key"
                ))
            }
        };

        Ok(Self { inner: key })
    }

    pub fn expand(&self) -> ExpandedOprfServerKey {
        match &self.inner {
            CompressedAtomicPatternOprfServerKey::KeySwitch32(ks32) => {
                ExpandedOprfServerKey::KeySwitch32(ks32.expand())
            }
            CompressedAtomicPatternOprfServerKey::Standard(std) => {
                ExpandedOprfServerKey::Standard(std.expand())
            }
        }
    }
}

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

// Different than the ShortintBootstrappingKey as the PRF uses its own modulus switch.
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

    fn assert_compatible_with_target_bsk(
        &self,
        target_input_lwe_dimension: LweDimension,
        target_output_lwe_dimension: LweDimension,
        target_polynomial_size: PolynomialSize,
    ) {
        assert_eq!(target_input_lwe_dimension, self.input_lwe_dimension());
        assert_eq!(target_output_lwe_dimension, self.output_lwe_dimension());
        assert_eq!(target_polynomial_size, self.polynomial_size());
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

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(AtomicPatternOprfServerKeyVersions)]
pub enum GenericAtomicPatternOprfServerKey<C: Container<Element = c64>> {
    KeySwitch32(OprfBootstrappingKey<C>),
    Standard(OprfBootstrappingKey<C>),
}

pub type AtomicPatternOprfServerKey = GenericAtomicPatternOprfServerKey<ABox<[c64]>>;

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(OprfServerKeyVersions)]
pub struct GenericOprfServerKey<C: Container<Element = c64>> {
    pub(crate) inner: GenericAtomicPatternOprfServerKey<C>,
}

pub type OprfServerKey = GenericOprfServerKey<ABox<[c64]>>;
pub type OprfServerKeyView<'a> = GenericOprfServerKey<&'a [c64]>;

// Shared methods for both owned and view types.
impl<C: Container<Element = c64> + Sync> GenericOprfServerKey<C> {
    pub fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext {
        match &self.inner {
            GenericAtomicPatternOprfServerKey::KeySwitch32(bsk) => {
                bsk.generate_oblivious_pseudo_random::<u32>(seed, random_bits_count, target_sks)
            }
            GenericAtomicPatternOprfServerKey::Standard(bsk) => {
                bsk.generate_oblivious_pseudo_random::<u64>(seed, random_bits_count, target_sks)
            }
        }
    }

    pub fn generate_oblivious_pseudo_random_message_and_carry(
        &self,
        seed: Seed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext {
        match &self.inner {
            GenericAtomicPatternOprfServerKey::KeySwitch32(bsk) => bsk
                .generate_oblivious_pseudo_random_message_and_carry::<u32>(
                    seed,
                    random_bits_count,
                    target_sks,
                ),
            GenericAtomicPatternOprfServerKey::Standard(bsk) => bsk
                .generate_oblivious_pseudo_random_message_and_carry::<u64>(
                    seed,
                    random_bits_count,
                    target_sks,
                ),
        }
    }
}

// Owned-only methods.
impl OprfServerKey {
    pub fn new(sk: &OprfPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        let key = match (&sk.0, &target_ck.atomic_pattern) {
            (
                AtomicPatternOprfPrivateKey::KeySwitch32(sk),
                AtomicPatternClientKey::KeySwitch32(ck),
            ) => ShortintEngine::with_thread_local_mut(|engine| {
                let bsk =
                    engine.new_oprf_bootstrapping_key_ks32(ck.parameters, sk, &ck.glwe_secret_key);

                GenericAtomicPatternOprfServerKey::KeySwitch32(bsk)
            }),
            (AtomicPatternOprfPrivateKey::Standard(sk), AtomicPatternClientKey::Standard(ck)) => {
                let bsk = ShortintEngine::with_thread_local_mut(|engine| {
                    engine.new_oprf_bootstrapping_key_standard(
                        ck.parameters,
                        sk,
                        &ck.glwe_secret_key,
                    )
                });
                GenericAtomicPatternOprfServerKey::Standard(bsk)
            }
            _ => {
                return Err(crate::error!(
                    "Mismatched atomic_patterns for oprf key and client key"
                ))
            }
        };

        Ok(Self { inner: key })
    }

    pub fn from_raw_parts(inner: AtomicPatternOprfServerKey) -> Self {
        Self { inner }
    }

    pub fn into_raw_parts(self) -> AtomicPatternOprfServerKey {
        self.inner
    }

    pub fn as_view(&self) -> OprfServerKeyView<'_> {
        let inner = match &self.inner {
            GenericAtomicPatternOprfServerKey::KeySwitch32(bsk) => {
                GenericAtomicPatternOprfServerKey::KeySwitch32(bsk.as_view())
            }
            GenericAtomicPatternOprfServerKey::Standard(bsk) => {
                GenericAtomicPatternOprfServerKey::Standard(bsk.as_view())
            }
        };
        GenericOprfServerKey { inner }
    }
}

impl ParameterSetConformant for AtomicPatternOprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (Self::Standard(bsk), AtomicPatternParameters::Standard(std_params)) => {
                let pbs_conformance_params: PBSConformanceParams = std_params.into();
                bsk.is_conformant(&pbs_conformance_params)
            }
            (Self::KeySwitch32(bsk), AtomicPatternParameters::KeySwitch32(ks32_params)) => {
                let pbs_conformance_params: PBSConformanceParams = ks32_params.into();
                bsk.is_conformant(&pbs_conformance_params)
            }
            _ => false,
        }
    }
}

impl ParameterSetConformant for OprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.inner.is_conformant(parameter_set)
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

impl ParameterSetConformant for CompressedAtomicPatternOprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (Self::Standard(bsk), AtomicPatternParameters::Standard(std_params)) => {
                let pbs_conformance_params: PBSConformanceParams = std_params.into();
                bsk.is_conformant(&pbs_conformance_params)
            }
            (Self::KeySwitch32(bsk), AtomicPatternParameters::KeySwitch32(ks32_params)) => {
                let pbs_conformance_params: PBSConformanceParams = ks32_params.into();
                bsk.is_conformant(&pbs_conformance_params)
            }
            _ => false,
        }
    }
}

impl ParameterSetConformant for CompressedOprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.inner.is_conformant(parameter_set)
    }
}

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

pub fn sha3_hash<Scalar>(values: &mut [Scalar], seed: Seed)
where
    Scalar: UnsignedInteger,
{
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hasher = sha3::Shake256::default();

    let bytes = seed.0.to_le_bytes();

    hasher.update(bytes.as_slice());

    let mut reader = hasher.finalize_xof();

    for value in values {
        let bytes = bytemuck::bytes_of_mut(value);
        reader.read(bytes);
        // On little endian machine this is a no op, on big endian it will swap the bytes
        *value = value.to_le();
    }
}
pub fn create_random_from_seed<Scalar>(seed: Seed, lwe_size: LweSize) -> LweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedInteger,
{
    // We use a native CiphertextModulus because the hash fills all the bits
    let mut ct = LweCiphertext::new(Scalar::ZERO, lwe_size, CiphertextModulus::new_native());

    sha3_hash(ct.get_mut_mask().as_mut(), seed);

    ct
}

pub(crate) fn create_random_from_seed_modulus_switched<Scalar>(
    seed: Seed,
    lwe_size: LweSize,
    log_modulus: CiphertextModulusLog,
) -> PrfSeededModulusSwitched
where
    Scalar: UnsignedInteger + CastInto<usize>,
{
    let ct = create_random_from_seed(seed, lwe_size);

    let mask = ct
        .get_mask()
        .as_ref()
        .iter()
        .map(|a: &Scalar| modulus_switch(*a, log_modulus).cast_into())
        .collect();

    let body = modulus_switch(*ct.get_body().data, log_modulus).cast_into();

    PrfSeededModulusSwitched {
        mask,
        body,
        log_modulus,
    }
}

#[allow(unused)]
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

impl<C: Container<Element = c64> + Sync> OprfBootstrappingKey<C> {
    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    /// `2^random_bits_count` must be smaller than the message modulus
    /// The encrypted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random<InputScalar>(
        &self,
        seed: Seed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext
    where
        InputScalar: UnsignedInteger + CastInto<usize>,
    {
        assert!(
            random_bits_count < 64,
            "random_bits_count >= 64 is not supported",
        );
        assert!(
            1 << random_bits_count <= target_sks.message_modulus.0,
            "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [0, {}[",
            random_bits_count, target_sks.message_modulus.0
        );

        self.generate_oblivious_pseudo_random_message_and_carry::<InputScalar>(
            seed,
            random_bits_count,
            target_sks,
        )
    }

    /// Uniformly generates a random value in `[0, 2^random_bits_count[`
    /// The encrypted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random_message_and_carry<InputScalar>(
        &self,
        seed: Seed,
        random_bits_count: u64,
        target_sks: &ServerKey,
    ) -> Ciphertext
    where
        InputScalar: UnsignedInteger + CastInto<usize>,
    {
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

        let ks_key = match &target_sks.atomic_pattern {
            AtomicPatternServerKey::Standard(std) => {
                self.assert_compatible_with_target_bsk(
                    std.bootstrapping_key.input_lwe_dimension(),
                    std.bootstrapping_key.output_lwe_dimension(),
                    std.bootstrapping_key.polynomial_size(),
                );

                match std.pbs_order {
                    PBSOrder::KeyswitchBootstrap => None,
                    PBSOrder::BootstrapKeyswitch => Some(&std.key_switching_key),
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32) => {
                self.assert_compatible_with_target_bsk(
                    ks32.bootstrapping_key.input_lwe_dimension(),
                    ks32.bootstrapping_key.output_lwe_dimension(),
                    ks32.bootstrapping_key.polynomial_size(),
                );
                None
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Dynamic atomic pattern does not support oprf")
            }
        };

        let (ct, degree) = self.generate_pseudo_random_from_pbs::<InputScalar>(
            seed,
            random_bits_count,
            1 + carry_bits_count + message_bits_count,
            target_sks.ciphertext_modulus,
        );

        let ct = match ks_key {
            Some(ks) => {
                let mut ct_ksed = LweCiphertext::new(
                    0,
                    ks.input_key_lwe_dimension().to_lwe_size(),
                    ks.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(ks, &ct, &mut ct_ksed);
                ct_ksed
            }
            None => ct,
        };

        Ciphertext::new(
            ct,
            degree,
            NoiseLevel::NOMINAL,
            target_sks.message_modulus,
            target_sks.carry_modulus,
            target_sks.atomic_pattern.kind(),
        )
    }

    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`, using a PBS.
    ///
    /// `full_bits_count` is the size of the lwe message, ie the shortint message + carry + padding
    /// bit.
    /// The output in in the form 0000rrr000noise (rbc=3, fbc=7)
    /// The encrypted value is oblivious to the server.
    ///
    /// It is the responsibility of the calling AP to transform this into a shortint ciphertext. The
    /// returned LWE is in the post PBS state, so a Keyswitch might be needed if the order is
    /// PBS-KS.
    fn generate_pseudo_random_from_pbs<InputScalar>(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
        ciphertext_modulus: CiphertextModulus<u64>,
    ) -> (LweCiphertextOwned<u64>, Degree)
    where
        InputScalar: UnsignedInteger + CastInto<usize>,
    {
        assert!(
        random_bits_count <= full_bits_count,
        "The number of random bits asked for (={random_bits_count}) is bigger than full_bits_count (={full_bits_count})"
    );

        let in_lwe_size = self.input_lwe_dimension().to_lwe_size();

        let polynomial_size = self.polynomial_size();
        let seeded: PrfSeededModulusSwitched =
            create_random_from_seed_modulus_switched::<InputScalar>(
                seed,
                in_lwe_size,
                polynomial_size.to_blind_rotation_input_modulus_log(),
            );

        let p = 1 << random_bits_count;
        let degree = p - 1;

        let delta = 1_u64 << (64 - full_bits_count);

        let poly_delta = 2 * polynomial_size.0 as u64 / p;

        let lut_size = LookupTableSize::new(self.glwe_size(), polynomial_size);
        let acc = generate_lookup_table_no_encode(lut_size, ciphertext_modulus, |x| {
            (2 * (x / poly_delta) + 1) * delta / 2
        });

        let out_lwe_size = self.output_lwe_dimension().to_lwe_size();

        let mut ct = LweCiphertext::new(0, out_lwe_size, ciphertext_modulus);

        let mut glwe_out = acc;

        match self {
            Self::Classic { bsk } => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    let buffers = engine.get_computation_buffers();

                    apply_standard_blind_rotate(bsk, &seeded, &mut glwe_out, buffers);
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
                    &mut glwe_out,
                    fourier_bsk,
                    *thread_count,
                    *deterministic_execution,
                );
            }
        }

        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut ct, MonomialDegree(0));

        lwe_ciphertext_plaintext_add_assign(&mut ct, Plaintext(degree * delta / 2));
        (ct, Degree(degree))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::core_crypto::prelude::{decrypt_lwe_ciphertext, CastInto, LweSecretKeyView};
    use crate::shortint::oprf::create_random_from_seed_modulus_switched;
    use crate::shortint::{ClientKey, ServerKey, ShortintParameterSet};
    use rayon::prelude::*;
    use statrs::distribution::ContinuousCDF;
    use std::collections::HashMap;
    use tfhe_csprng::seeders::Seed;

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

            for seed in 0..1000 {
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

        let img = oprf_sk.generate_oblivious_pseudo_random(seed, random_bits_count, &sk);

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

        let seeded = create_random_from_seed_modulus_switched::<Scalar>(
            seed,
            lwe_size,
            params
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
        );

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
}
