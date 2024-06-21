use super::{CompressionKey, CompressionPrivateKeys, DecompressionKey};
use crate::core_crypto::prelude::{
    allocate_and_generate_new_seeded_lwe_packing_keyswitch_key,
    par_allocate_and_generate_new_seeded_lwe_bootstrap_key,
    par_convert_standard_lwe_bootstrap_key_to_fourier, CiphertextModulusLog,
    FourierLweBootstrapKey, LweCiphertextCount, SeededLweBootstrapKeyOwned,
    SeededLwePackingKeyswitchKey,
};
use crate::shortint::backward_compatibility::list_compression::{
    CompressedCompressionKeyVersions, CompressedDecompressionKeyVersions,
};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::ShortintBootstrappingKey;
use crate::shortint::{ClassicPBSParameters, EncryptionKeyChoice, PBSParameters};
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
        let cks_params: ClassicPBSParameters = match self.parameters.pbs_parameters().unwrap() {
            PBSParameters::PBS(a) => a,
            PBSParameters::MultiBitPBS(_) => {
                panic!("Compression is currently not compatible with Multi Bit PBS")
            }
        };

        let params = &private_compression_key.params;

        assert_eq!(
            cks_params.encryption_key_choice,
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

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
