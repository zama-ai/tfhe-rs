use super::{
    CompressionConformanceParameters, CompressionKey, CompressionPrivateKeys, DecompressionKey,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::BootstrapKeyConformanceParams;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_seeded_lwe_packing_keyswitch_key,
    par_allocate_and_generate_new_seeded_lwe_bootstrap_key,
    par_convert_standard_lwe_bootstrap_key_to_fourier, CiphertextModulusLog,
    FourierLweBootstrapKey, LweCiphertextCount, PackingKeyswitchConformanceParams,
    SeededLweBootstrapKeyOwned, SeededLwePackingKeyswitchKey,
};
use crate::shortint::backward_compatibility::list_compression::{
    CompressedCompressionKeyVersions, CompressedDecompressionKeyVersions,
};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::{PBSConformanceParameters, ShortintBootstrappingKey};
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
            blind_rotate_key: ShortintBootstrappingKey::Classic(fourier_bsk),
            lwe_per_glwe: self.lwe_per_glwe,
        }
    }
}

impl ClientKey {
    pub fn new_compressed_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> (CompressedCompressionKey, CompressedDecompressionKey) {
        assert_eq!(
            self.parameters
                .pbs_parameters()
                .unwrap()
                .encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let params = &private_compression_key.params;

        let packing_key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_seeded_lwe_packing_keyswitch_key(
                &self.large_lwe_secret_key(),
                &private_compression_key.post_packing_ks_key,
                params.packing_ks_base_log,
                params.packing_ks_level,
                params.packing_ks_key_noise_distribution,
                self.parameters.ciphertext_modulus(),
                &mut engine.seeder,
            )
        });

        let glwe_compression_key = CompressedCompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: params.lwe_per_glwe,
            storage_log_modulus: params.storage_log_modulus,
        };

        let blind_rotate_key = ShortintEngine::with_thread_local_mut(|engine| {
            par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                &private_compression_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &self.glwe_secret_key,
                private_compression_key.params.br_base_log,
                private_compression_key.params.br_level,
                self.parameters.glwe_noise_distribution(),
                self.parameters.ciphertext_modulus(),
                &mut engine.seeder,
            )
        });

        let glwe_decompression_key = CompressedDecompressionKey {
            blind_rotate_key,
            lwe_per_glwe: params.lwe_per_glwe,
        };

        (glwe_compression_key, glwe_decompression_key)
    }
}

impl ParameterSetConformant for CompressedCompressionKey {
    type ParameterSet = CompressionConformanceParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            packing_key_switching_key,
            lwe_per_glwe,
            storage_log_modulus,
        } = self;

        let params = PackingKeyswitchConformanceParams {
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
    type ParameterSet = CompressionConformanceParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            blind_rotate_key,
            lwe_per_glwe,
        } = self;

        let params: PBSConformanceParameters = parameter_set.into();

        let params: BootstrapKeyConformanceParams = (&params).into();

        blind_rotate_key.is_conformant(&params) && *lwe_per_glwe == parameter_set.lwe_per_glwe
    }
}
