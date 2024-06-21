use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key, GlweSecretKeyOwned,
};
use crate::shortint::backward_compatibility::list_compression::CompressionPrivateKeysVersions;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::list_compression::CompressionParameters;
use crate::shortint::{ClassicPBSParameters, EncryptionKeyChoice, PBSParameters};
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
        let cks_params: ClassicPBSParameters = match self.parameters.pbs_parameters().unwrap() {
            PBSParameters::PBS(a) => a,
            PBSParameters::MultiBitPBS(_) => {
                panic!("Compression is currently not compatible with Multi Bit PBS")
            }
        };

        assert_eq!(
            cks_params.encryption_key_choice,
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
