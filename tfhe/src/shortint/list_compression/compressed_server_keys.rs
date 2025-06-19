use super::server_keys::NoiseSquashingCompressionKeyConformanceParams;
use super::{
    CompressionKey, CompressionKeyConformanceParams, CompressionPrivateKeys, DecompressionKey,
    NoiseSquashingCompressionKey,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_seeded_lwe_packing_keyswitch_key,
    par_allocate_and_generate_new_seeded_lwe_bootstrap_key,
    par_convert_standard_lwe_bootstrap_key_to_fourier, CiphertextModulusLog,
    FourierLweBootstrapKey, LweCiphertextCount, LwePackingKeyswitchKeyConformanceParams,
    SeededLweBootstrapKeyOwned, SeededLwePackingKeyswitchKey,
};
use crate::shortint::backward_compatibility::list_compression::{
    CompressedCompressionKeyVersions, CompressedDecompressionKeyVersions,
    CompressedNoiseSquashingCompressionKeyVersions,
};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::{
    ModulusSwitchConfiguration, PBSConformanceParams, ShortintBootstrappingKey,
};
use crate::shortint::EncryptionKeyChoice;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCompressionKeyVersions)]
pub struct CompressedCompressionKey {
    pub packing_key_switching_key: SeededLwePackingKeyswitchKey<Vec<u64>>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
}

impl CompressedCompressionKey {
    pub fn decompress(&self) -> CompressionKey {
        let packing_key_switching_key = self
            .packing_key_switching_key
            .as_view()
            .decompress_into_lwe_packing_keyswitch_key();

        CompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: self.lwe_per_glwe,
            storage_log_modulus: self.storage_log_modulus,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedDecompressionKeyVersions)]
pub struct CompressedDecompressionKey {
    pub blind_rotate_key: SeededLweBootstrapKeyOwned<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl CompressedDecompressionKey {
    pub fn decompress(&self) -> DecompressionKey {
        let blind_rotate_key = self
            .blind_rotate_key
            .as_view()
            .par_decompress_into_lwe_bootstrap_key();

        let mut fourier_bsk = FourierLweBootstrapKey::new(
            blind_rotate_key.input_lwe_dimension(),
            blind_rotate_key.glwe_size(),
            blind_rotate_key.polynomial_size(),
            blind_rotate_key.decomposition_base_log(),
            blind_rotate_key.decomposition_level_count(),
        );

        // Conversion to fourier domain
        par_convert_standard_lwe_bootstrap_key_to_fourier(&blind_rotate_key, &mut fourier_bsk);

        DecompressionKey {
            blind_rotate_key: ShortintBootstrappingKey::Classic {
                bsk: fourier_bsk,
                modulus_switch_noise_reduction_key: ModulusSwitchConfiguration::Plain,
            },
            lwe_per_glwe: self.lwe_per_glwe,
        }
    }
}

impl ClientKey {
    pub fn new_compressed_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> (CompressedCompressionKey, CompressedDecompressionKey) {
        let AtomicPatternClientKey::Standard(std_cks) = &self.atomic_pattern else {
            panic!("Only the standard atomic pattern supports compression")
        };

        let pbs_params = std_cks.parameters;

        assert_eq!(
            pbs_params.encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let compression_params = &private_compression_key.params;

        let packing_key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_seeded_lwe_packing_keyswitch_key(
                &std_cks.large_lwe_secret_key(),
                &private_compression_key.post_packing_ks_key,
                compression_params.packing_ks_base_log,
                compression_params.packing_ks_level,
                compression_params.packing_ks_key_noise_distribution,
                pbs_params.ciphertext_modulus(),
                &mut engine.seeder,
            )
        });

        let glwe_compression_key = CompressedCompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: compression_params.lwe_per_glwe,
            storage_log_modulus: compression_params.storage_log_modulus,
        };

        let blind_rotate_key = ShortintEngine::with_thread_local_mut(|engine| {
            par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                &private_compression_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &std_cks.glwe_secret_key,
                compression_params.br_base_log,
                compression_params.br_level,
                pbs_params.glwe_noise_distribution(),
                pbs_params.ciphertext_modulus(),
                &mut engine.seeder,
            )
        });

        let glwe_decompression_key = CompressedDecompressionKey {
            blind_rotate_key,
            lwe_per_glwe: compression_params.lwe_per_glwe,
        };

        (glwe_compression_key, glwe_decompression_key)
    }
}

impl ParameterSetConformant for CompressedCompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            packing_key_switching_key,
            lwe_per_glwe,
            storage_log_modulus,
        } = self;

        let params = LwePackingKeyswitchKeyConformanceParams {
            decomp_base_log: parameter_set.packing_ks_base_log,
            decomp_level_count: parameter_set.packing_ks_level,
            input_lwe_dimension: parameter_set
                .uncompressed_glwe_dimension
                .to_equivalent_lwe_dimension(parameter_set.uncompressed_polynomial_size),
            output_glwe_size: parameter_set.packing_ks_glwe_dimension.to_glwe_size(),
            output_polynomial_size: parameter_set.packing_ks_polynomial_size,
            ciphertext_modulus: parameter_set.cipherext_modulus,
        };

        packing_key_switching_key.is_conformant(&params)
            && *lwe_per_glwe == parameter_set.lwe_per_glwe
            && *storage_log_modulus == parameter_set.storage_log_modulus
    }
}

impl ParameterSetConformant for CompressedDecompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            blind_rotate_key,
            lwe_per_glwe,
        } = self;

        let params: PBSConformanceParams = parameter_set.into();

        let params: LweBootstrapKeyConformanceParams<_> = (&params).into();

        blind_rotate_key.is_conformant(&params) && *lwe_per_glwe == parameter_set.lwe_per_glwe
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingCompressionKeyVersions)]
pub struct CompressedNoiseSquashingCompressionKey {
    pub packing_key_switching_key: SeededLwePackingKeyswitchKey<Vec<u128>>,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl CompressedNoiseSquashingCompressionKey {
    pub fn decompress(&self) -> NoiseSquashingCompressionKey {
        let packing_key_switching_key = self
            .packing_key_switching_key
            .as_view()
            .decompress_into_lwe_packing_keyswitch_key();

        NoiseSquashingCompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: self.lwe_per_glwe,
        }
    }
}

impl ParameterSetConformant for CompressedNoiseSquashingCompressionKey {
    type ParameterSet = NoiseSquashingCompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            packing_key_switching_key,
            lwe_per_glwe,
        } = self;

        let params = LwePackingKeyswitchKeyConformanceParams {
            decomp_base_log: parameter_set.packing_ks_base_log,
            decomp_level_count: parameter_set.packing_ks_level,
            input_lwe_dimension: parameter_set
                .uncompressed_glwe_dimension
                .to_equivalent_lwe_dimension(parameter_set.uncompressed_polynomial_size),
            output_glwe_size: parameter_set.packing_ks_glwe_dimension.to_glwe_size(),
            output_polynomial_size: parameter_set.packing_ks_polynomial_size,
            ciphertext_modulus: parameter_set.cipherext_modulus,
        };

        packing_key_switching_key.is_conformant(&params)
            && *lwe_per_glwe == parameter_set.lwe_per_glwe
    }
}
