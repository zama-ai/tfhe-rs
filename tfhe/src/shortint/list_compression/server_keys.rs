use super::CompressionPrivateKeys;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_lwe_packing_keyswitch_key, CiphertextModulusLog, GlweSize,
    LweCiphertextCount, LwePackingKeyswitchKey,
};
use crate::shortint::backward_compatibility::list_compression::{
    CompressionKeyVersions, DecompressionKeyVersions,
};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::PolynomialSize;
use crate::shortint::server_key::ShortintBootstrappingKey;
use crate::shortint::{ClassicPBSParameters, EncryptionKeyChoice, PBSParameters};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressionKeyVersions)]
pub struct CompressionKey {
    pub packing_key_switching_key: LwePackingKeyswitchKey<Vec<u64>>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(DecompressionKeyVersions)]
pub struct DecompressionKey {
    pub blind_rotate_key: ShortintBootstrappingKey,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl DecompressionKey {
    pub fn out_glwe_size(&self) -> GlweSize {
        self.blind_rotate_key.glwe_size()
    }

    pub fn out_polynomial_size(&self) -> PolynomialSize {
        self.blind_rotate_key.polynomial_size()
    }
}

impl ClientKey {
    pub fn new_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> (CompressionKey, DecompressionKey) {
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
            allocate_and_generate_new_lwe_packing_keyswitch_key(
                &self.large_lwe_secret_key(),
                &private_compression_key.post_packing_ks_key,
                params.packing_ks_base_log,
                params.packing_ks_level,
                params.packing_ks_key_noise_distribution,
                self.parameters.ciphertext_modulus(),
                &mut engine.encryption_generator,
            )
        });

        assert!(
            private_compression_key.params.storage_log_modulus.0
                <= cks_params
                    .polynomial_size
                    .to_blind_rotation_input_modulus_log()
                    .0,
            "Compression parameters say to store more bits than useful"
        );

        let glwe_compression_key = CompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: params.lwe_per_glwe,
            storage_log_modulus: private_compression_key.params.storage_log_modulus,
        };

        let blind_rotate_key = ShortintEngine::with_thread_local_mut(|engine| {
            ShortintBootstrappingKey::Classic(
                engine.new_classic_bootstrapping_key(
                    &private_compression_key
                        .post_packing_ks_key
                        .as_lwe_secret_key(),
                    &self.glwe_secret_key,
                    self.parameters.glwe_noise_distribution(),
                    private_compression_key.params.br_base_log,
                    private_compression_key.params.br_level,
                    self.parameters.ciphertext_modulus(),
                ),
            )
        });

        let glwe_decompression_key = DecompressionKey {
            blind_rotate_key,
            lwe_per_glwe: params.lwe_per_glwe,
        };

        (glwe_compression_key, glwe_decompression_key)
    }
}
