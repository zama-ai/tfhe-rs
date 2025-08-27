//! Module with the definition of the CompressedServerKey.

use super::{MaxDegree, PBSConformanceParams, PbsTypeConformanceParams};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::*;
use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::backward_compatibility::server_key::{
    CompressedServerKeyVersions, ShortintCompressedBootstrappingKeyVersions,
};
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CiphertextModulus, MessageModulus, ModulusSwitchType,
};
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, ModulusSwitchNoiseReductionKeyConformanceParams,
    ShortintBootstrappingKey,
};
use crate::shortint::{ClientKey, ServerKey};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ShortintCompressedBootstrappingKeyVersions)]
pub enum ShortintCompressedBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    Classic {
        bsk: SeededLweBootstrapKeyOwned<u64>,
        modulus_switch_noise_reduction_key: CompressedModulusSwitchConfiguration<InputScalar>,
    },
    MultiBit {
        seeded_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
        deterministic_execution: bool,
    },
}

impl<InputScalar> ShortintCompressedBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    pub fn input_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic { bsk, .. } => bsk.input_lwe_dimension(),
            Self::MultiBit {
                seeded_bsk: inner, ..
            } => inner.input_lwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic { bsk, .. } => bsk.polynomial_size(),
            Self::MultiBit {
                seeded_bsk: inner, ..
            } => inner.polynomial_size(),
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        match self {
            Self::Classic { bsk, .. } => bsk.glwe_size(),
            Self::MultiBit {
                seeded_bsk: inner, ..
            } => inner.glwe_size(),
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::Classic { bsk, .. } => bsk.decomposition_base_log(),
            Self::MultiBit {
                seeded_bsk: inner, ..
            } => inner.decomposition_base_log(),
        }
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        match self {
            Self::Classic { bsk, .. } => bsk.decomposition_level_count(),
            Self::MultiBit {
                seeded_bsk: inner, ..
            } => inner.decomposition_level_count(),
        }
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic { bsk, .. } => bsk.output_lwe_dimension(),
            Self::MultiBit {
                seeded_bsk: inner, ..
            } => inner.output_lwe_dimension(),
        }
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Classic { bsk, .. } => bsk.ciphertext_modulus(),
            Self::MultiBit {
                seeded_bsk: inner, ..
            } => inner.ciphertext_modulus(),
        }
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        match self {
            Self::Classic { bsk, .. } => bsk.as_view().into_container().len(),
            Self::MultiBit {
                seeded_bsk: bsk, ..
            } => bsk.as_view().into_container().len(),
        }
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        match self {
            Self::Classic { bsk, .. } => std::mem::size_of_val(bsk.as_view().into_container()),
            Self::MultiBit {
                seeded_bsk: bsk, ..
            } => std::mem::size_of_val(bsk.as_view().into_container()),
        }
    }
}

impl<InputScalar: UnsignedTorus> ShortintCompressedBootstrappingKey<InputScalar> {
    pub fn decompress(&self) -> ShortintBootstrappingKey<InputScalar> {
        match self {
            Self::Classic {
                bsk: compressed_bootstrapping_key,
                modulus_switch_noise_reduction_key,
            } => {
                let (fourier_bsk, modulus_switch_noise_reduction_key) = rayon::join(
                    || {
                        let decompressed_bootstrapping_key = compressed_bootstrapping_key
                            .as_view()
                            .par_decompress_into_lwe_bootstrap_key();

                        let mut fourier_bsk = FourierLweBootstrapKeyOwned::new(
                            decompressed_bootstrapping_key.input_lwe_dimension(),
                            decompressed_bootstrapping_key.glwe_size(),
                            decompressed_bootstrapping_key.polynomial_size(),
                            decompressed_bootstrapping_key.decomposition_base_log(),
                            decompressed_bootstrapping_key.decomposition_level_count(),
                        );

                        par_convert_standard_lwe_bootstrap_key_to_fourier(
                            &decompressed_bootstrapping_key,
                            &mut fourier_bsk,
                        );

                        fourier_bsk
                    },
                    || modulus_switch_noise_reduction_key.decompress(),
                );

                ShortintBootstrappingKey::Classic {
                    bsk: fourier_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                seeded_bsk: compressed_bootstrapping_key,
                deterministic_execution,
            } => {
                let decompressed_bootstrapping_key = compressed_bootstrapping_key
                    .as_view()
                    .par_decompress_into_lwe_multi_bit_bootstrap_key();

                let mut fourier_bsk = FourierLweMultiBitBootstrapKeyOwned::new(
                    decompressed_bootstrapping_key.input_lwe_dimension(),
                    decompressed_bootstrapping_key.glwe_size(),
                    decompressed_bootstrapping_key.polynomial_size(),
                    decompressed_bootstrapping_key.decomposition_base_log(),
                    decompressed_bootstrapping_key.decomposition_level_count(),
                    decompressed_bootstrapping_key.grouping_factor(),
                );

                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(
                    &decompressed_bootstrapping_key,
                    &mut fourier_bsk,
                );

                let thread_count = ShortintEngine::get_thread_count_for_multi_bit_pbs(
                    fourier_bsk.input_lwe_dimension(),
                    fourier_bsk.glwe_size().to_glwe_dimension(),
                    fourier_bsk.polynomial_size(),
                    fourier_bsk.decomposition_base_log(),
                    fourier_bsk.decomposition_level_count(),
                    fourier_bsk.grouping_factor(),
                );

                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution: *deterministic_execution,
                }
            }
        }
    }
}

/// A structure containing a compressed server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedServerKeyVersions)]
pub struct CompressedServerKey {
    pub compressed_ap_server_key: CompressedAtomicPatternServerKey,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
}

impl CompressedServerKey {
    /// Generate a compressed server key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::server_key::CompressedServerKey;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let sks = CompressedServerKey::new(&cks);
    /// ```
    pub fn new(client_key: &ClientKey) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_compressed_server_key(client_key))
    }

    /// Decompress a [`CompressedServerKey`] into a [`ServerKey`].
    pub fn decompress(&self) -> ServerKey {
        let Self {
            compressed_ap_server_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        } = self;

        let message_modulus = *message_modulus;
        let carry_modulus = *carry_modulus;
        let max_degree = *max_degree;
        let max_noise_level = *max_noise_level;
        let ciphertext_modulus = compressed_ap_server_key.ciphertext_modulus();

        ServerKey {
            atomic_pattern: compressed_ap_server_key.decompress(),
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
        }
    }

    /// Deconstruct a [`CompressedServerKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        CompressedAtomicPatternServerKey,
        MessageModulus,
        CarryModulus,
        MaxDegree,
        MaxNoiseLevel,
    ) {
        let Self {
            compressed_ap_server_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        } = self;

        (
            compressed_ap_server_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        )
    }

    /// Construct a [`CompressedServerKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw_parts(
        compressed_ap_server_key: CompressedAtomicPatternServerKey,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        max_degree: MaxDegree,
        max_noise_level: MaxNoiseLevel,
    ) -> Self {
        let max_max_degree = MaxDegree::from_msg_carry_modulus(message_modulus, carry_modulus);

        assert!(
            max_degree.get() <= max_max_degree.get(),
            "Maximum valid MaxDegree is {max_max_degree:?}, got ({max_degree:?})"
        );

        Self {
            compressed_ap_server_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        }
    }

    /// Generate a compressed server key with a chosen maximum degree
    pub fn new_with_max_degree(cks: &ClientKey, max_degree: MaxDegree) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_compressed_server_key_with_max_degree(cks, max_degree)
        })
    }

    pub(crate) fn as_compressed_standard_atomic_pattern_server_key(
        &self,
    ) -> Option<&CompressedStandardAtomicPatternServerKey> {
        match &self.compressed_ap_server_key {
            CompressedAtomicPatternServerKey::Standard(
                compressed_standard_atomic_pattern_server_key,
            ) => Some(compressed_standard_atomic_pattern_server_key),
            CompressedAtomicPatternServerKey::KeySwitch32(_) => None,
        }
    }

    pub fn ciphertext_lwe_dimension(&self) -> LweDimension {
        self.compressed_ap_server_key.ciphertext_lwe_dimension()
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        self.compressed_ap_server_key.ciphertext_modulus()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        match &self.compressed_ap_server_key {
            CompressedAtomicPatternServerKey::Standard(
                compressed_standard_atomic_pattern_server_key,
            ) => compressed_standard_atomic_pattern_server_key
                .bootstrapping_key()
                .bootstrapping_key_size_bytes(),
            CompressedAtomicPatternServerKey::KeySwitch32(
                compressed_ks32_atomic_pattern_server_key,
            ) => compressed_ks32_atomic_pattern_server_key
                .bootstrapping_key()
                .bootstrapping_key_size_bytes(),
        }
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        match &self.compressed_ap_server_key {
            CompressedAtomicPatternServerKey::Standard(
                compressed_standard_atomic_pattern_server_key,
            ) => compressed_standard_atomic_pattern_server_key
                .bootstrapping_key()
                .bootstrapping_key_size_elements(),
            CompressedAtomicPatternServerKey::KeySwitch32(
                compressed_ks32_atomic_pattern_server_key,
            ) => compressed_ks32_atomic_pattern_server_key
                .bootstrapping_key()
                .bootstrapping_key_size_elements(),
        }
    }
}

impl<InputScalar> ParameterSetConformant for ShortintCompressedBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    type ParameterSet = PBSConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set.pbs_type) {
            (
                Self::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                },
                PbsTypeConformanceParams::Classic {
                    modulus_switch_noise_reduction,
                },
            ) => {
                let modulus_switch_noise_reduction_key_conformant = match (
                    modulus_switch_noise_reduction_key,
                    modulus_switch_noise_reduction,
                ) {
                    (
                        CompressedModulusSwitchConfiguration::Standard,
                        ModulusSwitchType::Standard,
                    ) => true,

                    (
                        CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction,
                        ModulusSwitchType::CenteredMeanNoiseReduction,
                    ) => true,
                    (
                        CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        ),
                        ModulusSwitchType::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_params,
                        ),
                    ) => {
                        let param = ModulusSwitchNoiseReductionKeyConformanceParams {
                            modulus_switch_noise_reduction_params,
                            lwe_dimension: parameter_set.in_lwe_dimension,
                        };

                        modulus_switch_noise_reduction_key.is_conformant(&param)
                    }
                    _ => false,
                };

                let param: LweBootstrapKeyConformanceParams<_> = parameter_set.into();

                bsk.is_conformant(&param) && modulus_switch_noise_reduction_key_conformant
            }
            (
                Self::MultiBit {
                    seeded_bsk,
                    deterministic_execution: _,
                },
                PbsTypeConformanceParams::MultiBit { .. },
            ) => {
                let param = parameter_set.try_into();

                param.is_ok_and(|param| seeded_bsk.is_conformant(&param))
            }
            _ => false,
        }
    }
}

impl ParameterSetConformant for CompressedServerKey {
    type ParameterSet = (AtomicPatternParameters, MaxDegree);

    fn is_conformant(&self, (parameter_set, expected_max_degree): &Self::ParameterSet) -> bool {
        let Self {
            compressed_ap_server_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        } = self;

        let compressed_ap_server_key_ok = compressed_ap_server_key.is_conformant(parameter_set);

        compressed_ap_server_key_ok
            && *max_degree == *expected_max_degree
            && *message_modulus == parameter_set.message_modulus()
            && *carry_modulus == parameter_set.carry_modulus()
            && *max_noise_level == parameter_set.max_noise_level()
    }
}
