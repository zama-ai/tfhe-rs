use crate::core_crypto::algorithms::glwe_secret_key_generation::allocate_and_generate_new_binary_glwe_secret_key;
use crate::core_crypto::algorithms::lwe_encryption::decrypt_lwe_ciphertext;
use crate::core_crypto::entities::glwe_secret_key::GlweSecretKeyOwned;
use crate::shortint::backward_compatibility::noise_squashing::NoiseSquashingPrivateKeyVersions;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::CarryModulus;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingPrivateKeyVersions)]
pub struct NoiseSquashingPrivateKey {
    post_noise_squashing_secret_key: GlweSecretKeyOwned<u128>,
    params: NoiseSquashingParameters,
}

impl NoiseSquashingPrivateKey {
    pub fn new(client_key: &ClientKey, params: NoiseSquashingParameters) -> Self {
        client_key.new_noise_squashing_private_key(params)
    }

    pub fn decrypt_squashed_noise_ciphertext(&self, ciphertext: &SquashedNoiseCiphertext) -> u128 {
        let plaintext = decrypt_lwe_ciphertext(
            &self.post_noise_squashing_secret_key.as_lwe_secret_key(),
            ciphertext.lwe_ciphertext(),
        );

        let encoding = ShortintEncoding {
            ciphertext_modulus: self.params.ciphertext_modulus,
            message_modulus: ciphertext.message_modulus(),
            carry_modulus: CarryModulus(1),
            padding_bit: PaddingBit::Yes,
        };

        encoding.decode(plaintext).0
    }

    pub fn post_noise_squashing_secret_key(&self) -> &GlweSecretKeyOwned<u128> {
        &self.post_noise_squashing_secret_key
    }

    pub fn noise_squashing_parameters(&self) -> NoiseSquashingParameters {
        self.params
    }
}

impl ClientKey {
    pub fn new_noise_squashing_private_key(
        &self,
        params: NoiseSquashingParameters,
    ) -> NoiseSquashingPrivateKey {
        let post_noise_squashing_secret_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut engine.secret_generator,
            )
        });

        NoiseSquashingPrivateKey {
            post_noise_squashing_secret_key,
            params,
        }
    }
}

impl From<NoiseSquashingCompressionPrivateKey> for NoiseSquashingPrivateKey {
    fn from(value: NoiseSquashingCompressionPrivateKey) -> Self {
        Self {
            post_noise_squashing_secret_key: value.post_packing_ks_key,
            params: NoiseSquashingParameters {
                glwe_dimension: value.params.packing_ks_glwe_dimension,
                polynomial_size: value.params.packing_ks_polynomial_size,
                glwe_noise_distribution: value.params.packing_ks_key_noise_distribution,
                decomp_base_log: value.params.packing_ks_base_log,
                decomp_level_count: value.params.packing_ks_level,
                modulus_switch_noise_reduction_params: None,
                ciphertext_modulus: value.params.ciphertext_modulus,
            },
        }
    }
}
