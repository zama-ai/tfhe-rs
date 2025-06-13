use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key, GlweSecretKeyOwned,
};
use crate::shortint::backward_compatibility::list_compression::{
    CompressionPrivateKeysVersions, NoiseSquashingCompressionPrivateKeyVersions,
};
use crate::shortint::ciphertext::CompressedSquashedNoiseCiphertextList;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::noise_squashing::NoiseSquashingPrivateKeyView;
use crate::shortint::parameters::{CompressionParameters, NoiseSquashingCompressionParameters};
use crate::shortint::EncryptionKeyChoice;
use std::fmt::Debug;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressionPrivateKeysVersions)]
pub struct CompressionPrivateKeys {
    pub post_packing_ks_key: GlweSecretKeyOwned<u64>,
    pub params: CompressionParameters,
}

impl ClientKey {
    pub fn new_compression_private_key(
        &self,
        params: CompressionParameters,
    ) -> CompressionPrivateKeys {
        assert_eq!(
            self.parameters()
                .pbs_parameters()
                .unwrap()
                .encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let post_packing_ks_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.packing_ks_glwe_dimension,
                params.packing_ks_polynomial_size,
                &mut engine.secret_generator,
            )
        });

        CompressionPrivateKeys {
            post_packing_ks_key,
            params,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(NoiseSquashingCompressionPrivateKeyVersions)]
pub struct NoiseSquashingCompressionPrivateKey {
    pub(crate) post_packing_ks_key: GlweSecretKeyOwned<u128>,
    pub(crate) params: NoiseSquashingCompressionParameters,
}

impl NoiseSquashingCompressionPrivateKey {
    pub fn new(params: NoiseSquashingCompressionParameters) -> Self {
        let post_packing_ks_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.packing_ks_glwe_dimension,
                params.packing_ks_polynomial_size,
                &mut engine.secret_generator,
            )
        });

        Self {
            post_packing_ks_key,
            params,
        }
    }

    /// Extract and decrypt all the ciphertexts in the list
    pub fn unpack_and_decrypt_squashed_noise_ciphertexts(
        &self,
        compressed_list: &CompressedSquashedNoiseCiphertextList,
    ) -> Vec<u128> {
        let decryption_key = NoiseSquashingPrivateKeyView::from(self);
        (0..compressed_list.len())
            .map(|i| {
                let ciphertext = compressed_list.unpack(i).unwrap(); // i is smaller than list size

                decryption_key.decrypt_squashed_noise_ciphertext(&ciphertext)
            })
            .collect()
    }
}
