//! Module with the definition of the CompressedServerKey.

use super::{
    CompressedModulusSwitchNoiseReductionKey, MaxDegree,
    ModulusSwitchNoiseReductionKeyConformanceParams, PBSConformanceParams,
    PbsTypeConformanceParams,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::*;
use crate::shortint::atomic_pattern::ClassicalAtomicPatternServerKey;
use crate::shortint::backward_compatibility::server_key::{
    CompressedServerKeyVersions, ShortintCompressedBootstrappingKeyVersions,
};
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CarryModulus, CiphertextModulus, MessageModulus};
use crate::shortint::server_key::ShortintBootstrappingKey;
use crate::shortint::{ClientKey, PBSParameters, ServerKey};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ShortintCompressedBootstrappingKeyVersions)]
pub enum ShortintCompressedBootstrappingKey {
    Classic {
        bsk: SeededLweBootstrapKeyOwned<u64>,
        modulus_switch_noise_reduction_key: Option<CompressedModulusSwitchNoiseReductionKey>,
    },
    MultiBit {
        seeded_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
        deterministic_execution: bool,
    },
}

impl ShortintCompressedBootstrappingKey {
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

/// A structure containing a compressed server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedServerKeyVersions)]
pub struct CompressedServerKey {
    pub key_switching_key: SeededLweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintCompressedBootstrappingKey,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
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
            key_switching_key: compressed_key_switching_key,
            bootstrapping_key: compressed_bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        } = self;

        let (key_switching_key, bootstrapping_key) = rayon::join(
            || {
                compressed_key_switching_key
                    .as_view()
                    .par_decompress_into_lwe_keyswitch_key()
            },
            || match compressed_bootstrapping_key {
                ShortintCompressedBootstrappingKey::Classic {
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
                        || {
                            modulus_switch_noise_reduction_key.as_ref().map(
                                |modulus_switch_noise_reduction_key| {
                                    modulus_switch_noise_reduction_key.decompress()
                                },
                            )
                        },
                    );

                    ShortintBootstrappingKey::Classic {
                        bsk: fourier_bsk,
                        modulus_switch_noise_reduction_key,
                    }
                }
                ShortintCompressedBootstrappingKey::MultiBit {
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

                    let thread_count = ShortintEngine::with_thread_local_mut(|engine| {
                        engine.get_thread_count_for_multi_bit_pbs(
                            fourier_bsk.input_lwe_dimension(),
                            fourier_bsk.glwe_size().to_glwe_dimension(),
                            fourier_bsk.polynomial_size(),
                            fourier_bsk.decomposition_base_log(),
                            fourier_bsk.decomposition_level_count(),
                            fourier_bsk.grouping_factor(),
                        )
                    });

                    ShortintBootstrappingKey::MultiBit {
                        fourier_bsk,
                        thread_count,
                        deterministic_execution: *deterministic_execution,
                    }
                }
            },
        );

        let message_modulus = *message_modulus;
        let carry_modulus = *carry_modulus;
        let max_degree = *max_degree;
        let max_noise_level = *max_noise_level;
        let ciphertext_modulus = *ciphertext_modulus;
        let pbs_order = *pbs_order;

        let atomic_pattern = ClassicalAtomicPatternServerKey::from_raw_parts(
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        );

        ServerKey {
            atomic_pattern: atomic_pattern.into(),
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
        SeededLweKeyswitchKeyOwned<u64>,
        ShortintCompressedBootstrappingKey,
        MessageModulus,
        CarryModulus,
        MaxDegree,
        MaxNoiseLevel,
        CiphertextModulus,
        PBSOrder,
    ) {
        let Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        } = self;

        (
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        )
    }

    /// Construct a [`CompressedServerKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw_parts(
        key_switching_key: SeededLweKeyswitchKeyOwned<u64>,
        bootstrapping_key: ShortintCompressedBootstrappingKey,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        max_degree: MaxDegree,
        max_noise_level: MaxNoiseLevel,
        ciphertext_modulus: CiphertextModulus,
        pbs_order: PBSOrder,
    ) -> Self {
        assert_eq!(
            key_switching_key.input_key_lwe_dimension(),
            bootstrapping_key.output_lwe_dimension(),
            "Mismatch between the input SeededLweKeyswitchKeyOwned LweDimension ({:?}) \
            and the ShortintCompressedBootstrappingKey output LweDimension ({:?})",
            key_switching_key.input_key_lwe_dimension(),
            bootstrapping_key.output_lwe_dimension()
        );

        assert_eq!(
            key_switching_key.output_key_lwe_dimension(),
            bootstrapping_key.input_lwe_dimension(),
            "Mismatch between the output SeededLweKeyswitchKeyOwned LweDimension ({:?}) \
            and the ShortintCompressedBootstrappingKey input LweDimension ({:?})",
            key_switching_key.output_key_lwe_dimension(),
            bootstrapping_key.input_lwe_dimension()
        );

        assert_eq!(
            key_switching_key.ciphertext_modulus(),
            ciphertext_modulus,
            "Mismatch between the SeededLweKeyswitchKeyOwned CiphertextModulus ({:?}) \
            and the provided CiphertextModulus ({:?})",
            key_switching_key.ciphertext_modulus(),
            ciphertext_modulus
        );

        assert_eq!(
            bootstrapping_key.ciphertext_modulus(),
            ciphertext_modulus,
            "Mismatch between the ShortintCompressedBootstrappingKey CiphertextModulus ({:?}) \
            and the provided CiphertextModulus ({:?})",
            bootstrapping_key.ciphertext_modulus(),
            ciphertext_modulus
        );

        let max_max_degree = MaxDegree::from_msg_carry_modulus(message_modulus, carry_modulus);

        assert!(
            max_degree.get() <= max_max_degree.get(),
            "Maximum valid MaxDegree is {max_max_degree:?}, got ({max_degree:?})"
        );

        Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        }
    }

    /// Generate a compressed server key with a chosen maximum degree
    pub fn new_with_max_degree(cks: &ClientKey, max_degree: MaxDegree) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_compressed_server_key_with_max_degree(cks, max_degree)
        })
    }

    pub fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_dimension(),
        }
    }
}

impl ParameterSetConformant for ShortintCompressedBootstrappingKey {
    type ParameterSet = PBSConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set.pbs_type) {
            (
                Self::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                },
                PbsTypeConformanceParams::Classic { .. },
            ) => {
                let modulus_switch_noise_reduction_key_conformant = match (
                    modulus_switch_noise_reduction_key,
                    ModulusSwitchNoiseReductionKeyConformanceParams::try_from(parameter_set),
                ) {
                    (None, Err(())) => true,
                    (Some(modulus_switch_noise_reduction_key), Ok(param)) => {
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
                let param: MultiBitBootstrapKeyConformanceParams =
                    parameter_set.try_into().unwrap();

                seeded_bsk.is_conformant(&param)
            }
            _ => false,
        }
    }
}

impl ParameterSetConformant for CompressedServerKey {
    type ParameterSet = (PBSParameters, MaxDegree);

    fn is_conformant(&self, (parameter_set, expected_max_degree): &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        } = self;

        let params: PBSConformanceParams = parameter_set.into();

        let pbs_key_ok = bootstrapping_key.is_conformant(&params);

        let param: LweKeyswitchKeyConformanceParams = parameter_set.into();

        let ks_key_ok = key_switching_key.is_conformant(&param);

        let pbs_order_ok = matches!(
            (*pbs_order, parameter_set.encryption_key_choice()),
            (PBSOrder::KeyswitchBootstrap, EncryptionKeyChoice::Big)
                | (PBSOrder::BootstrapKeyswitch, EncryptionKeyChoice::Small)
        );

        pbs_key_ok
            && ks_key_ok
            && pbs_order_ok
            && *max_degree == *expected_max_degree
            && *message_modulus == parameter_set.message_modulus()
            && *carry_modulus == parameter_set.carry_modulus()
            && *max_noise_level == parameter_set.max_noise_level()
            && *ciphertext_modulus == parameter_set.ciphertext_modulus()
    }
}
